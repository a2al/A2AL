// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// a2ald is the A2AL daemon: DHT/QUIC host, REST API, Web UI, TCP gateway, MCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/daemon"
	"github.com/a2al/a2al/internal/version"
)

// openBrowser opens url in the default system browser.
// On headless Linux (no DISPLAY / WAYLAND_DISPLAY) it returns immediately
// without attempting anything.  All other errors are silently discarded.
func openBrowser(url string) {
	if runtime.GOOS == "linux" &&
		os.Getenv("DISPLAY") == "" &&
		os.Getenv("WAYLAND_DISPLAY") == "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func main() {
	dataDir := flag.String("data-dir", "", "data directory (default: UserConfigDir/a2al)")
	cfgPath := flag.String("config", "", "path to config.toml (default: <data-dir>/config.toml)")
	listen := flag.String("listen", "", "override Tangled Network (UDP) listen address")
	apiAddr := flag.String("api-addr", "", "override REST API listen address")
	fallbackHost := flag.String("fallback-host", "", "advertised host when no public IP is detected")
	bootstrapFlag := flag.String("bootstrap", "", "comma-separated bootstrap peers (appended to config)")
	mcpStdio := flag.Bool("mcp-stdio", false, "run MCP server on stdin/stdout instead of HTTP API")
	noBrowser := flag.Bool("no-open-browser", false, "do not open the Web UI in a browser on startup")
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

	// Load config once to get open_browser and api_addr for browser launch.
	// Errors are silently ignored — daemon.New will report them properly.
	webCfg := config.Default()
	cfgFile := *cfgPath
	if cfgFile == "" {
		cfgFile = filepath.Join(dd, "config.toml")
	}
	if c, err := config.LoadFile(cfgFile); err == nil {
		webCfg = c
	}
	apiURL := "http://" + webCfg.APIAddr
	if *apiAddr != "" {
		apiURL = "http://" + *apiAddr
	}
	if webCfg.OpenBrowser && !*noBrowser && !*mcpStdio {
		go func() {
			time.Sleep(500 * time.Millisecond)
			openBrowser(apiURL)
		}()
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
