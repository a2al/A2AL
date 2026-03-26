// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package config holds Phase 3 daemon TOML settings (library layer; daemon owns persistence).
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config is the a2ald configuration (spec Phase 3).
type Config struct {
	ListenAddr       string   `toml:"listen_addr"`
	QUICListenAddr   string   `toml:"quic_listen_addr"`
	Bootstrap        []string `toml:"bootstrap"`
	DisableUPnP      bool     `toml:"disable_upnp"`
	FallbackHost     string   `toml:"fallback_host"`
	MinObservedPeers int      `toml:"min_observed_peers"`
	APIAddr          string   `toml:"api_addr"`
	APIToken         string   `toml:"api_token"`
	KeyDir           string   `toml:"key_dir"`
	LogFormat        string   `toml:"log_format"`
	LogLevel         string   `toml:"log_level"`

	ICESignalURL    string   `toml:"ice_signal_url"`
	ICESTUNURLs     []string `toml:"ice_stun_urls"`
	ICETURNURLs     []string `toml:"ice_turn_urls"`
	ICEPublishTurns []string `toml:"ice_publish_turns"`
}

// Default returns a copy with zero values filled to spec defaults.
func Default() Config {
	return Config{
		ListenAddr:       ":4121",
		QUICListenAddr:   "",
		Bootstrap:        nil,
		DisableUPnP:      false,
		FallbackHost:     "",
		MinObservedPeers: 3,
		APIAddr:          "127.0.0.1:2121",
		APIToken:         "",
		KeyDir:           "",
		LogFormat:        "text",
		LogLevel:         "info",
	}
}

// Validate returns an error if fields are invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr required")
	}
	if c.APIAddr == "" {
		return fmt.Errorf("config: api_addr required")
	}
	if c.LogFormat != "" && c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("config: log_format must be text or json")
	}
	if c.ICESignalURL != "" {
		u, err := url.Parse(c.ICESignalURL)
		if err != nil {
			return fmt.Errorf("config: invalid ice_signal_url: %v", err)
		}
		if u.Scheme != "ws" && u.Scheme != "wss" {
			return fmt.Errorf("config: ice_signal_url must use ws:// or wss:// scheme")
		}
	}
	for _, t := range c.ICEPublishTurns {
		if strings.Contains(t, "@") {
			return fmt.Errorf("config: ice_publish_turns must not contain credentials (found '@' in %q)", t)
		}
	}
	return nil
}

// KeyDirOrDefault returns the directory for node.key; empty KeyDir means <dataDir>/keys.
func (c *Config) KeyDirOrDefault(dataDir string) string {
	if c.KeyDir != "" {
		return c.KeyDir
	}
	return filepath.Join(dataDir, "keys")
}

// LoadFile reads TOML from path into a new Config merged over Default().
func LoadFile(path string) (Config, error) {
	base := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := toml.Unmarshal(b, &base); err != nil {
		return Config{}, err
	}
	return base, nil
}

// Save writes c to path as TOML (0644) via a temp-file rename for atomicity.
func Save(path string, c Config) error {
	b, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ApplyEnv overlays known A2AL_* variables (subset).
func ApplyEnv(c *Config) {
	if v := os.Getenv("A2AL_DATA_DIR"); v != "" {
		// Interpreted by daemon main for paths only; not stored in this struct.
		_ = v
	}
	if v := os.Getenv("A2AL_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("A2AL_API_ADDR"); v != "" {
		c.APIAddr = v
	}
	if v := os.Getenv("A2AL_API_TOKEN"); v != "" {
		c.APIToken = v
	}
	if v := os.Getenv("A2AL_FALLBACK_HOST"); v != "" {
		c.FallbackHost = v
	}
	if v := os.Getenv("A2AL_DISABLE_UPNP"); v != "" {
		c.DisableUPnP = strings.EqualFold(v, "1") || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("A2AL_ICE_SIGNAL_URL"); v != "" {
		c.ICESignalURL = v
	}
}

// RestartRequiredKeys lists config keys that need daemon restart after change.
var RestartRequiredKeys = []string{
	"listen_addr", "quic_listen_addr", "bootstrap", "api_addr", "key_dir",
	"disable_upnp", "fallback_host", "min_observed_peers",
	"ice_signal_url", "ice_stun_urls", "ice_turn_urls", "ice_publish_turns",
}
