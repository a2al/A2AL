// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package daemon implements the a2ald runtime: DHT/QUIC host, REST API, TCP
// gateway, and MCP server. It is shared by the CLI binary (cmd/a2ald) and the
// mobile binding (mobile/).
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/peerscache"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/signaling"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Config is the startup configuration for New.
type Config struct {
	// DataDir is the directory for keys, agents.json, peers.cache, and
	// config.toml. Required.
	DataDir string
	// CfgPath overrides the default config file path (DataDir/config.toml).
	CfgPath string
	// Override is called after the config is loaded, allowing the caller to
	// apply additional overrides (e.g., CLI flags).
	Override func(*config.Config)
	// Log is the structured logger to use. Defaults to text output on Stdout.
	Log *slog.Logger
	// MCPStdio runs the MCP server on stdin/stdout instead of HTTP.
	MCPStdio bool
}

// Daemon is the a2ald runtime.
type Daemon struct {
	dataDir  string
	cfgPath  string
	cfg      *config.Config
	log      *slog.Logger
	h        *host.Host
	reg      *registry.Registry
	nodeAddr a2al.Address
	regMu    sync.RWMutex

	mcpOnce sync.Once
	mcpSrv  *mcp.Server

	// mailboxSeen prevents duplicate delivery of mailbox messages within a
	// daemon session (DHT records persist until TTL expiry).
	mailboxSeenMu sync.Mutex
	mailboxSeen   map[string]map[string]time.Time // aidStr → msgKey → first-seen time

	nodePublishMu  sync.Mutex
	nodePublishSeq uint64 // last successfully published DHT seq for node identity

	publishMetaMu    sync.Mutex
	nodeLastPublish  time.Time
	lastEndpointsFP  string // for detecting IP / endpoint list changes
	agentLastPublish map[a2al.Address]time.Time

	heartbeatMu sync.Mutex
	heartbeatAt map[a2al.Address]time.Time

	iceRegNotify chan struct{} // ICE /signal registration refresh (buffered)
	gatewayConns atomic.Int64  // active gateway QUIC conns (direct + ICE)

	netMu                sync.Mutex
	netStableFP          string
	netPendingFP         string
	netPendingAt         time.Time
	netChangeTimes       []time.Time
	nodePublishQuietTill time.Time
	deferredEndpointEval bool
	netChangeNotify      chan struct{} // confirmed network-change events (buffered)
	netCascadeRunning    bool
	netFingerprintFn     func() string
	testNowFn            func() time.Time
	testGuardRepublishFn func(context.Context)
	testGuardCascadeFn   func(context.Context)

	rebootstrapMu          sync.Mutex
	lastRebootstrapAt      time.Time
	testMaybeRebootstrapFn func(context.Context) // if set, maybeRebootstrap calls this instead
}

// APIAddr returns the REST API / Web UI listen address from the loaded config.
func (d *Daemon) APIAddr() string { return d.cfg.APIAddr }

// New loads config, generates or loads the node key, and initialises the host.
// Call Run to start serving.
func New(cfg Config) (*Daemon, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("daemon: DataDir is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}

	cfgPath := cfg.CfgPath
	if cfgPath == "" {
		cfgPath = filepath.Join(cfg.DataDir, "config.toml")
	}
	nodeCfg, err := loadConfig(cfgPath, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.Override != nil {
		cfg.Override(&nodeCfg)
	}
	if err := nodeCfg.Validate(); err != nil {
		return nil, err
	}
	// Write default config if not present.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		_ = config.Save(cfgPath, nodeCfg)
	}

	log := cfg.Log
	if log == nil {
		level := slog.LevelInfo
		switch strings.ToLower(strings.TrimSpace(nodeCfg.LogLevel)) {
		case "debug":
			level = slog.LevelDebug
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
		opts := &slog.HandlerOptions{Level: level}
		var h slog.Handler
		if strings.ToLower(strings.TrimSpace(nodeCfg.LogFormat)) == "json" {
			h = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			h = slog.NewTextHandler(os.Stdout, opts)
		}
		log = slog.New(h)
	}

	keyPath := filepath.Join(nodeCfg.KeyDirOrDefault(cfg.DataDir), "node.key")
	ks, err := nodeks.LoadOrGenerate(keyPath)
	if err != nil {
		return nil, err
	}

	reg, err := registry.Load(filepath.Join(cfg.DataDir, "agents.json"))
	if err != nil {
		return nil, err
	}

	h, err := host.New(host.Config{
		KeyStore:         ks,
		ListenAddr:       nodeCfg.ListenAddr,
		QUICListenAddr:   nodeCfg.QUICListenAddr,
		MinObservedPeers: nodeCfg.MinObservedPeers,
		FallbackHost:     nodeCfg.FallbackHost,
		DisableUPnP:      nodeCfg.DisableUPnP,
		ICESignalURL:     nodeCfg.ICESignalURL,
		ICESignalURLs:    nodeCfg.ICESignalURLs,
		ICESTUNURLs:      nodeCfg.ICESTUNURLs,
		ICETURNURLs:      nodeCfg.ICETURNURLs,
		TURNServers:      toHostTURNServers(nodeCfg.TURNServers),
		ICEPublishTurns:  nodeCfg.ICEPublishTurns,
		Logger:           log,
		SeenPeersPath:    filepath.Join(cfg.DataDir, "seen_peers.dat"),
	})
	if err != nil {
		return nil, err
	}

	return &Daemon{
		dataDir:          cfg.DataDir,
		cfgPath:          cfgPath,
		cfg:              &nodeCfg,
		log:              log,
		h:                h,
		reg:              reg,
		nodeAddr:         ks.Address(),
		agentLastPublish: make(map[a2al.Address]time.Time),
		heartbeatAt:      make(map[a2al.Address]time.Time),
		mailboxSeen:      make(map[string]map[string]time.Time),
		iceRegNotify:     make(chan struct{}, 1),
		netChangeNotify:  make(chan struct{}, 1),
	}, nil
}

// toHostTURNServers converts config.TURNServerConfig slice to host.TURNServer slice,
// mapping the string credential_type field to the typed host constant.
func toHostTURNServers(cfgs []config.TURNServerConfig) []host.TURNServer {
	out := make([]host.TURNServer, 0, len(cfgs))
	for _, c := range cfgs {
		ts := host.TURNServer{
			URL:           c.URL,
			Username:      c.Username,
			Credential:    c.Credential,
			CredentialURL: c.CredentialURL,
		}
		switch c.CredentialType {
		case "hmac":
			ts.CredentialType = host.TURNCredentialHMAC
		case "rest_api":
			ts.CredentialType = host.TURNCredentialRESTAPI
		default: // "static" or empty
			ts.CredentialType = host.TURNCredentialStatic
		}
		out = append(out, ts)
	}
	return out
}

// Run starts the daemon and blocks until ctx is cancelled. It saves the peers
// cache and config on return.
func (d *Daemon) Run(ctx context.Context, mcpStdio bool) error {
	var closeSignalHub func()
	if addr := resolveSignalListenAddr(d.cfg); addr != "" {
		hub, err := signaling.ListenHub(addr)
		if err != nil {
			d.log.Warn("signal hub listen", "addr", addr, "err", err)
		} else {
			d.h.SetSignalStatsProvider(hub.StatsMap)
			closeSignalHub = func() { _ = hub.Close() }
			d.log.Info("signal hub listening", "addr", hub.Addr().String())
		}
	}
	defer func() {
		if closeSignalHub != nil {
			closeSignalHub()
		}
		savePeersCache(filepath.Join(d.dataDir, "peers.cache"), d.h, d.log)
		_ = d.h.Close()
	}()

	d.log.Info("a2ald starting",
		"node_aid", d.nodeAddr.String(),
		"dht", d.cfg.ListenAddr,
		"api", d.cfg.APIAddr,
	)

	// Re-register persisted agents (fast, local).
	for _, e := range d.reg.List() {
		if err := d.h.RegisterDelegatedAgent(e.AID, e.OpPriv, e.DelegationCBOR); err != nil {
			d.log.Warn("re-register agent", "aid", e.AID.String(), "err", err)
		}
	}

	netCtx, netCancel := context.WithCancel(ctx)
	defer netCancel()

	// Network init runs fully in the background: bootstrap → initial publish →
	// republish loop. HTTP / MCP server is available immediately; DHT operations
	// (resolve, discover, publish) will return errors or empty results until
	// bootstrap completes, which is correct behaviour.
	go func() {
		if derived := runBootstrapChain(netCtx, d.h, d.cfg, d.dataDir, d.log); derived != "" {
			d.h.SetDerivedICESignalURL(derived)
		}
		d.h.RunNATProbe(netCtx) // active NAT classification after bootstrap
		d.initialAutoPublish(netCtx)
		go d.runICEListener(netCtx)
		d.autoPublishMainLoop(netCtx)
	}()
	go d.runNetworkMonitor(netCtx)

	go d.gatewayAcceptLoop(netCtx)

	if mcpStdio {
		d.log.Info("a2ald ready",
			"dht", d.cfg.ListenAddr,
			"node_aid", d.nodeAddr.String(),
		)
		if err := d.mcpInstance().Run(ctx, mcp.NewStdioTransport()); mcpRunErr(err) {
			return err
		}
		return nil
	}

	mux := d.routes()
	srv := &http.Server{
		Addr:              d.cfg.APIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("http server", "err", err)
		}
	}()

	d.log.Info("a2ald ready",
		"api", d.cfg.APIAddr,
		"browser", "http://"+d.cfg.APIAddr,
		"dht", d.cfg.ListenAddr,
		"node_aid", d.nodeAddr.String(),
	)

	<-ctx.Done()
	d.log.Info("shutting down")
	netCancel()
	shctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = srv.Shutdown(shctx)
	return nil
}

func loadConfig(cfgPath, dataDir string) (config.Config, error) {
	cfg := config.Default()
	config.ApplyEnv(&cfg)
	if _, err := os.Stat(cfgPath); err == nil {
		loaded, err := config.LoadFile(cfgPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg = loaded
		config.ApplyEnv(&cfg)
	}
	if cfg.KeyDir == "" {
		cfg.KeyDir = filepath.Join(dataDir, "keys")
	}
	return cfg, nil
}

// savePeersCache persists known DHT peer addresses for the next cold start.
func savePeersCache(path string, h *host.Host, log *slog.Logger) {
	addrs := h.Node().BootstrapCandidateAddrs(64)
	strs := make([]string, 0, len(addrs))
	seen := make(map[string]struct{})
	for _, a := range addrs {
		s := addrToHostPort(a)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		strs = append(strs, s)
	}
	if err := peerscache.Save(path, strs); err != nil {
		log.Warn("peers.cache save", "err", err)
	}
}

func mcpRunErr(err error) bool {
	if err == nil {
		return false
	}
	// stdio transport returns io.EOF on clean close.
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}
