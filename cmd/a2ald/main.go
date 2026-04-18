// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// a2ald is the A2AL daemon: DHT/QUIC host, REST API, Web UI, TCP gateway, MCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/daemon"
	"github.com/a2al/a2al/internal/version"
)

func main() {
	dataDir := flag.String("data-dir", "", "data directory (default: UserConfigDir/a2al)")
	cfgPath := flag.String("config", "", "path to config.toml (default: <data-dir>/config.toml)")
	listen := flag.String("listen", "", "override Tangled Network (UDP) listen address")
	apiAddr := flag.String("api-addr", "", "override REST API listen address")
	fallbackHost := flag.String("fallback-host", "", "advertised host when no public IP is detected")
	bootstrapFlag := flag.String("bootstrap", "", "comma-separated bootstrap peers (appended to config)")
	mcpStdio := flag.Bool("mcp-stdio", false, "run MCP server on stdin/stdout instead of HTTP API")
	flag.Parse()

	fmt.Fprintln(os.Stderr, version.Banner("a2ald", "A2AL Daemon"))

	dd := *dataDir
	if dd == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "a2ald: UserConfigDir:", err)
			os.Exit(1)
		}
		dd = base + "/a2al"
	}

	d, err := daemon.New(daemon.Config{
		DataDir: dd,
		CfgPath: *cfgPath,
		Override: func(cfg *config.Config) {
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
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := d.Run(ctx, *mcpStdio); err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(1)
	}
}
