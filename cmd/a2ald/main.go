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

	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/daemon"
	"github.com/a2al/a2al/internal/updater"
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
	// Internal subcommand: smoke-test — validates the binary before replacing
	// the running daemon. Not user-facing; called by the updater subprocess.
	// Format: a2ald __smoke-test --data-dir <path>
	if len(os.Args) > 1 && os.Args[1] == "__smoke-test" {
		handleSmokeTest(os.Args[2:])
		return
	}

	// "service" subcommand: handle before banner and flag parsing.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		handleServiceCmd(os.Args[2:])
		return
	}

	// "update" subcommand: check or apply updates via the running daemon API.
	if len(os.Args) > 1 && os.Args[1] == "update" {
		handleUpdateCmd(os.Args[2:])
		return
	}

	dataDir := flag.String("data-dir", "", "data directory (default: UserConfigDir/a2al)")
	cfgPath := flag.String("config", "", "path to config.toml (default: <data-dir>/config.toml)")
	listen := flag.String("listen", "", "override Tangled Network (UDP) listen address")
	apiAddr := flag.String("api-addr", "", "override REST API listen address")
	fallbackHost := flag.String("fallback-host", "", "advertised host when no public IP is detected")
	bootstrapFlag := flag.String("bootstrap", "", "comma-separated bootstrap peers (appended to config)")
	mcpStdio := flag.Bool("mcp-stdio", false, "run MCP server on stdin/stdout instead of HTTP API")
	noBrowser := flag.Bool("no-open-browser", false, "do not open the Web UI in a browser on startup")
	flag.Parse()

	dd := *dataDir
	if dd == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "a2ald: UserConfigDir:", err)
			os.Exit(1)
		}
		dd = base + "/a2al"
	}

	// Check for a pending update from the previous run; may roll back and os.Exit(0).
	updater.CheckAndRollback(dd)

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

	// --mcp-stdio: if a daemon is already running, proxy stdio MCP to it.
	// The MCP client gets the warm DHT state immediately with no cold-start wait,
	// and no data-dir lock conflict occurs.
	if *mcpStdio && probeHTTPDaemon(apiURL) {
		fmt.Fprintln(os.Stderr, "a2ald: existing daemon detected; proxying stdio MCP to", apiURL)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := proxyMCPStdio(ctx, apiURL+"/mcp/"); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald:", err)
			os.Exit(1)
		}
		return
	}

	// Suppress the banner when running as a Windows SCM service (no console).
	if !isRunningAsService() {
		fmt.Fprintln(os.Stderr, version.Banner("a2ald", "A2AL Daemon"))
	}

	if webCfg.OpenBrowser && !*noBrowser && !*mcpStdio && !isRunningAsService() {
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

	// When started by Windows SCM, delegate control to the service handler.
	if isRunningAsService() {
		if err := runServiceMain(d); err != nil {
			os.Exit(1)
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := d.Run(ctx, *mcpStdio); err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(1)
	}
}

// handleSmokeTest is called with args == os.Args[2:] when the process is
// invoked as "a2ald __smoke-test --data-dir <path>".
func handleSmokeTest(args []string) {
	fs := flag.NewFlagSet("smoke-test", flag.ExitOnError)
	dd := fs.String("data-dir", "", "")
	_ = fs.Parse(args)
	if *dd == "" {
		// fall back to default data dir
		base, _ := os.UserConfigDir()
		*dd = base + "/a2al"
	}
	if err := updater.RunSmokeTest(*dd); err != nil {
		fmt.Fprintln(os.Stderr, "smoke-test:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// handleUpdateCmd implements "a2ald update [--check]". Both modes call the
// running daemon's REST API; the daemon must be running.
func handleUpdateCmd(args []string) {
	fs := flag.NewFlagSet("a2ald update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "check for updates without applying")
	dd := fs.String("data-dir", "", "data directory (to locate API address)")
	_ = fs.Parse(args)

	apiURL := resolveAPIURL(*dd)

	if *checkOnly {
		resp, err := http.Get(apiURL + "/update/status") //nolint:gosec
		if err != nil {
			fmt.Fprintln(os.Stderr, "a2ald: cannot reach daemon:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var out bytes.Buffer
		_ = json.Indent(&out, body, "", "  ")
		fmt.Println(out.String())
		return
	}

	resp, err := http.Post(apiURL+"/update/apply", "application/json", nil) //nolint:gosec
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald: cannot reach daemon:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out bytes.Buffer
	_ = json.Indent(&out, body, "", "  ")
	fmt.Println(out.String())
}

// resolveAPIURL reads the config file from dd to determine the daemon API address.
func resolveAPIURL(dd string) string {
	if dd == "" {
		base, _ := os.UserConfigDir()
		dd = base + "/a2al"
	}
	cfg := config.Default()
	if c, err := config.LoadFile(filepath.Join(dd, "config.toml")); err == nil {
		cfg = c
	}
	return "http://" + cfg.APIAddr
}
