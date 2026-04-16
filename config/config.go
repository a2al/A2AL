// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package config holds Phase 3 daemon TOML settings (library layer; daemon owns persistence).
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// TURNServerConfig is the TOML/JSON-serializable form of a TURN relay server.
// CredentialType selects the credential method: "static" (default), "hmac", or "rest_api".
type TURNServerConfig struct {
	URL            string `toml:"url" json:"url"`
	CredentialType string `toml:"credential_type" json:"credential_type"`
	Username       string `toml:"username" json:"username"`
	// Credential is the static password (static), HMAC shared secret (hmac),
	// or Authorization header value for the REST API call (rest_api).
	Credential    string `toml:"credential" json:"credential"`
	CredentialURL string `toml:"credential_url" json:"credential_url"`
}

// Config is the a2ald configuration (spec Phase 3).
type Config struct {
	ListenAddr       string   `toml:"listen_addr" json:"listen_addr"`
	QUICListenAddr   string   `toml:"quic_listen_addr" json:"quic_listen_addr"`
	Bootstrap        []string `toml:"bootstrap" json:"bootstrap"`
	DisableUPnP      bool     `toml:"disable_upnp" json:"disable_upnp"`
	FallbackHost     string   `toml:"fallback_host" json:"fallback_host"`
	MinObservedPeers int      `toml:"min_observed_peers" json:"min_observed_peers"`
	APIAddr          string   `toml:"api_addr" json:"api_addr"`
	APIToken         string   `toml:"api_token" json:"api_token"`
	KeyDir           string   `toml:"key_dir" json:"key_dir"`
	LogFormat        string   `toml:"log_format" json:"log_format"`
	LogLevel         string   `toml:"log_level" json:"log_level"`

	ICESignalURL  string   `toml:"ice_signal_url" json:"ice_signal_url"`
	ICESignalURLs []string `toml:"ice_signal_urls" json:"ice_signal_urls"`
	ICESTUNURLs   []string `toml:"ice_stun_urls" json:"ice_stun_urls"`
	// ICETURNURLs is the legacy TURN URL list with embedded credentials (user:pass@host).
	// Use TURNServers for new deployments.
	ICETURNURLs []string `toml:"ice_turn_urls" json:"ice_turn_urls"`
	// TURNServers lists TURN relay servers with structured credential configuration.
	TURNServers []TURNServerConfig `toml:"turn_servers" json:"turn_servers"`
	// ICEPublishTurns is deprecated; new nodes do not publish turns[] to the DHT.
	ICEPublishTurns []string `toml:"ice_publish_turns" json:"ice_publish_turns"`
	// SignalListenAddr is the TCP listen address for the embedded ICE signaling hub.
	// Empty or "off" disables the hub (default). Only enable on bootstrap/infrastructure nodes.
	// E.g. ":4121" shares the DHT port over TCP.
	SignalListenAddr string `toml:"signal_listen_addr" json:"signal_listen_addr"`
	// AutoPublish controls whether the daemon publishes the node identity to the DHT
	// on startup and on a schedule (default true). When false, the node stays off the DHT
	// as a discoverable endpoint while still participating in routing.
	AutoPublish bool `toml:"auto_publish" json:"auto_publish"`
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
		AutoPublish:      true,
		SignalListenAddr: "off",
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
	for i, su := range c.ICESignalURLs {
		u, err := url.Parse(su)
		if err != nil {
			return fmt.Errorf("config: invalid ice_signal_urls[%d]: %v", i, err)
		}
		if u.Scheme != "ws" && u.Scheme != "wss" {
			return fmt.Errorf("config: ice_signal_urls[%d] must use ws:// or wss:// scheme", i)
		}
	}
	for i, ts := range c.TURNServers {
		if ts.URL == "" {
			return fmt.Errorf("config: turn_servers[%d]: url required", i)
		}
		if strings.Contains(ts.URL, "@") {
			return fmt.Errorf("config: turn_servers[%d]: url must not contain credentials (use username/credential fields)", i)
		}
		switch ts.CredentialType {
		case "", "static", "hmac":
		case "rest_api":
			if ts.CredentialURL == "" {
				return fmt.Errorf("config: turn_servers[%d]: credential_url required for rest_api", i)
			}
		default:
			return fmt.Errorf("config: turn_servers[%d]: credential_type must be static, hmac, or rest_api", i)
		}
	}
	if s := strings.TrimSpace(c.SignalListenAddr); s != "" && !strings.EqualFold(s, "off") {
		addr := s
		if strings.HasPrefix(addr, ":") {
			addr = "0.0.0.0" + addr
		}
		if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
			return fmt.Errorf("config: signal_listen_addr: %w", err)
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
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
	if v := os.Getenv("A2AL_SIGNAL_LISTEN_ADDR"); v != "" {
		c.SignalListenAddr = v
	}
	if v := os.Getenv("A2AL_AUTO_PUBLISH"); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "0", "false", "no", "off":
			c.AutoPublish = false
		case "1", "true", "yes", "on":
			c.AutoPublish = true
		}
	}
}

// RestartRequiredKeys lists config keys that need daemon restart after change.
var RestartRequiredKeys = []string{
	"listen_addr", "quic_listen_addr", "bootstrap", "api_addr", "key_dir",
	"disable_upnp", "fallback_host", "min_observed_peers",
	"ice_signal_url", "ice_signal_urls", "ice_stun_urls", "ice_turn_urls",
	"turn_servers", "ice_publish_turns", "signal_listen_addr",
}
