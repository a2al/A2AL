// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.ListenAddr != ":4121" {
		t.Fatalf("ListenAddr: got %q", c.ListenAddr)
	}
	if c.APIAddr != "127.0.0.1:2121" {
		t.Fatalf("APIAddr: got %q", c.APIAddr)
	}
	if c.MinObservedPeers != 3 {
		t.Fatalf("MinObservedPeers: got %d", c.MinObservedPeers)
	}
	if c.LogFormat != "text" || c.LogLevel != "info" {
		t.Fatalf("log defaults: format=%q level=%q", c.LogFormat, c.LogLevel)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.ListenAddr = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "listen_addr") {
		t.Fatalf("want listen_addr error, got %v", err)
	}
	c = Default()
	c.APIAddr = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "api_addr") {
		t.Fatalf("want api_addr error, got %v", err)
	}
	c = Default()
	c.LogFormat = "yaml"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "log_format") {
		t.Fatalf("want log_format error, got %v", err)
	}
}

func TestKeyDirOrDefault(t *testing.T) {
	c := Default()
	if got := c.KeyDirOrDefault("/data"); got != filepath.Join("/data", "keys") {
		t.Fatalf("KeyDirOrDefault: got %q", got)
	}
	c.KeyDir = "/custom/keys"
	if got := c.KeyDirOrDefault("/data"); got != "/custom/keys" {
		t.Fatalf("KeyDirOrDefault custom: got %q", got)
	}
}

func TestLoadFileSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	want := Default()
	want.ListenAddr = ":6001"
	want.APIAddr = "127.0.0.1:9999"
	want.Bootstrap = []string{"1.2.3.4:5001"}
	want.LogFormat = "json"
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenAddr != want.ListenAddr || got.APIAddr != want.APIAddr {
		t.Fatalf("round-trip: %+v vs %+v", got.ListenAddr, want.ListenAddr)
	}
	if len(got.Bootstrap) != 1 || got.Bootstrap[0] != "1.2.3.4:5001" {
		t.Fatalf("Bootstrap: %#v", got.Bootstrap)
	}
	if got.LogFormat != "json" {
		t.Fatalf("LogFormat: %q", got.LogFormat)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFile_mergeOverDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	if err := os.WriteFile(path, []byte(`api_addr = "127.0.0.1:1"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":4121" {
		t.Fatalf("merged default listen_addr: got %q", c.ListenAddr)
	}
	if c.APIAddr != "127.0.0.1:1" {
		t.Fatalf("from file: got %q", c.APIAddr)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("A2AL_LISTEN_ADDR", ":7777")
	t.Setenv("A2AL_API_ADDR", "127.0.0.1:8888")
	t.Setenv("A2AL_API_TOKEN", "secret")
	t.Setenv("A2AL_FALLBACK_HOST", "example.com")
	t.Setenv("A2AL_DISABLE_UPNP", "true")
	c := Default()
	ApplyEnv(&c)
	if c.ListenAddr != ":7777" || c.APIAddr != "127.0.0.1:8888" {
		t.Fatalf("listen/api: %q %q", c.ListenAddr, c.APIAddr)
	}
	if c.APIToken != "secret" || c.FallbackHost != "example.com" {
		t.Fatalf("token/fallback")
	}
	if !c.DisableUPnP {
		t.Fatal("DisableUPnP want true")
	}
}
