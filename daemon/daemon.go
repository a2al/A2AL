// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/peerscache"
	"github.com/a2al/a2al/internal/registry"
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
	mailboxSeen   map[string]map[string]struct{} // aidStr → set of msgKey
}

// APIAddr returns the REST API / Web UI listen address from the loaded config.
func (d *Daemon) APIAddr() string { return d.cfg.APIAddr }

// New loads config, generates or loads the node key, and initialises the host.
// Call Run to start serving.
func New(cfg Config) (*Daemon, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("daemon: DataDir is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
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
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
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
	})
	if err != nil {
		return nil, err
	}

	return &Daemon{
		dataDir:  cfg.DataDir,
		cfgPath:  cfgPath,
		cfg:      &nodeCfg,
		log:      log,
		h:        h,
		reg:      reg,
		nodeAddr: ks.Address(),
	}, nil
}

// Run starts the daemon and blocks until ctx is cancelled. It saves the peers
// cache and config on return.
func (d *Daemon) Run(ctx context.Context, mcpStdio bool) error {
	defer func() {
		savePeersCache(filepath.Join(d.dataDir, "peers.cache"), d.h, d.log)
		_ = d.h.Close()
		_ = config.Save(d.cfgPath, *d.cfg)
	}()

	runBootstrapChain(ctx, d.h, d.cfg, d.dataDir, d.log)

	for _, e := range d.reg.List() {
		if err := d.h.RegisterDelegatedAgent(e.AID, e.OpPriv, e.DelegationCBOR); err != nil {
			d.log.Warn("re-register agent", "aid", e.AID.String(), "err", err)
		}
	}

	gwCtx, gwCancel := context.WithCancel(ctx)
	defer gwCancel()
	go d.gatewayAcceptLoop(gwCtx)

	if mcpStdio {
		d.log.Info("a2ald MCP stdio", "dht", d.cfg.ListenAddr, "node_aid", d.nodeAddr.String())
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

	d.log.Info("a2ald started",
		"api", d.cfg.APIAddr,
		"webui", "http://"+d.cfg.APIAddr,
		"dht", d.cfg.ListenAddr,
		"node_aid", d.nodeAddr.String(),
	)

	<-ctx.Done()
	d.log.Info("shutting down")
	gwCancel()
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
