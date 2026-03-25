// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// a2ald is the Phase 3 A2AL daemon: DHT/QUIC host, REST API, TCP gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/a2al/a2al/cmd/a2ald/internal/nodeks"
	"github.com/a2al/a2al/cmd/a2ald/internal/registry"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	dataDir := flag.String("data-dir", "", "data directory (default: UserConfigDir/a2al)")
	cfgPathFlag := flag.String("config", "", "path to config.toml (default: <data-dir>/config.toml)")
	listen := flag.String("listen", "", "override DHT listen address")
	apiAddr := flag.String("api-addr", "", "override REST API listen address")
	fallbackHost := flag.String("fallback-host", "", "advertised host when no public IP is detected (e.g. 127.0.0.1 for local tests)")
	bootstrapFlag := flag.String("bootstrap", "", "comma-separated bootstrap peers, e.g. 127.0.0.1:5001,1.2.3.4:5001 (appended to config)")
	mcpStdio := flag.Bool("mcp-stdio", false, "run MCP server on stdin/stdout instead of HTTP API")
	flag.Parse()

	dd := *dataDir
	if dd == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "a2ald: UserConfigDir:", err)
			os.Exit(1)
		}
		dd = filepath.Join(base, "a2al")
	}
	cfgPath := *cfgPathFlag
	if cfgPath == "" {
		cfgPath = filepath.Join(dd, "config.toml")
	}

	cfg, err := loadConfig(cfgPath, dd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: config:", err)
		os.Exit(1)
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if *apiAddr != "" {
		cfg.APIAddr = *apiAddr
	}
	if *fallbackHost != "" {
		cfg.FallbackHost = *fallbackHost
	}
	if *bootstrapFlag != "" {
		for _, s := range strings.Split(*bootstrapFlag, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.Bootstrap = append(cfg.Bootstrap, s)
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(dd, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: data dir:", err)
		os.Exit(1)
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := config.Save(cfgPath, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald: write default config:", err)
			os.Exit(1)
		}
	}

	keyPath := filepath.Join(cfg.KeyDirOrDefault(dd), "node.key")
	ks, err := nodeks.LoadOrGenerate(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: node key:", err)
		os.Exit(1)
	}

	log := newLogger(cfg)
	regPath := filepath.Join(dd, "agents.json")
	reg, err := registry.Load(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: agents registry:", err)
		os.Exit(1)
	}

	h, err := host.New(host.Config{
		KeyStore:         ks,
		ListenAddr:       cfg.ListenAddr,
		QUICListenAddr:   cfg.QUICListenAddr,
		MinObservedPeers: cfg.MinObservedPeers,
		FallbackHost:     cfg.FallbackHost,
		DisableUPnP:      cfg.DisableUPnP,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: host:", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	defer func() {
		savePeersCache(filepath.Join(dd, "peers.cache"), h, log)
		_ = h.Close()
	}()

	runBootstrapChain(ctx, h, &cfg, dd, log)

	// Re-register persisted agents on the QUIC mux.
	for _, e := range reg.List() {
		if err := h.RegisterDelegatedAgent(e.AID, e.OpPriv, e.DelegationCBOR); err != nil {
			log.Warn("re-register agent", "aid", e.AID.String(), "err", err)
		}
	}

	d := &daemon{
		dataDir:  dd,
		cfgPath:  cfgPath,
		cfg:      &cfg,
		log:      log,
		h:        h,
		reg:      reg,
		nodeAddr: ks.Address(),
	}

	gwCtx, gwCancel := context.WithCancel(ctx)
	defer gwCancel()
	go d.gatewayAcceptLoop(gwCtx)

	if *mcpStdio {
		log.Info("a2ald MCP stdio", "dht", cfg.ListenAddr, "node_aid", ks.Address().String())
		if err := d.mcpInstance().Run(ctx, mcp.NewStdioTransport()); mcpRunErr(err) {
			log.Error("mcp stdio", "err", err)
		}
		gwCancel()
		_ = config.Save(cfgPath, *d.cfg)
		return
	}

	mux := d.routes()
	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
		}
	}()

	log.Info("a2ald started", "api", cfg.APIAddr, "webui", "GET /", "mcp", "/mcp/", "dht", cfg.ListenAddr, "node_aid", ks.Address().String())

	<-ctx.Done()
	log.Info("shutting down")
	gwCancel()
	shctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = srv.Shutdown(shctx)
	_ = config.Save(cfgPath, *d.cfg)
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

func newLogger(cfg config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}
