// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package mobile exposes the a2ald daemon to Android and iOS via gomobile bind.
//
// Usage from a native shell App:
//
//	err := mobile.Start(dataDir)   // call once on app launch
//	url := mobile.WebUIAddr()      // load in WKWebView / WebView
//	mobile.Stop()                  // call on app terminate
package mobile

import (
	"context"
	"errors"
	"sync"

	"github.com/a2al/a2al/daemon"
)

var (
	mu      sync.Mutex
	cancelFn context.CancelFunc
	apiAddr  string
)

// Start launches the a2ald daemon in the background.
// dataDir is the app-specific writable directory (e.g. from Context.getFilesDir() on Android,
// or NSDocumentDirectory on iOS).
// Returns an error if already running or if initialisation fails.
func Start(dataDir string) error {
	mu.Lock()
	defer mu.Unlock()
	if cancelFn != nil {
		return errors.New("a2al: daemon already running; call Stop first")
	}
	d, err := daemon.New(daemon.Config{DataDir: dataDir})
	if err != nil {
		return err
	}
	apiAddr = d.APIAddr()
	ctx, cancel := context.WithCancel(context.Background())
	cancelFn = cancel
	go func() {
		_ = d.Run(ctx, false)
	}()
	return nil
}

// Stop shuts down the daemon gracefully.
// It is safe to call Stop even if the daemon is not running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if cancelFn != nil {
		cancelFn()
		cancelFn = nil
		apiAddr = ""
	}
}

// WebUIAddr returns the full URL of the REST API / Web UI
// (e.g. "http://127.0.0.1:2121"). Load this in a WebView after Start returns.
func WebUIAddr() string {
	mu.Lock()
	defer mu.Unlock()
	if apiAddr == "" {
		return ""
	}
	return "http://" + apiAddr
}

// IsRunning reports whether the daemon is currently active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return cancelFn != nil
}
