// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/peerscache"
	"github.com/a2al/a2al/signaling"
	"log/slog"
)

const dnsBootstrapName = "_a2al-bootstrap.a2al.org"

// runBootstrapChain joins the DHT, then derives an ICE signal base URL from a
// trusted source (config or DNS TXT only). peers.cache is used for fast DHT
// cold-start but is explicitly excluded from signal URL derivation, since it
// contains arbitrary DHT peers rather than designated signaling infrastructure.
func runBootstrapChain(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger) string {
	if !bootstrapDHT(ctx, h, cfg, dataDir, log) {
		log.Info("no bootstrap peers reachable, starting as standalone node")
		return ""
	}
	return deriveSignalURL(cfg, log)
}

// bootstrapDHT tries peers.cache → config → DNS TXT in order until one succeeds.
func bootstrapDHT(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger) bool {
	cachePath := filepath.Join(dataDir, "peers.cache")
	if lines, err := peerscache.Load(cachePath); err == nil && len(lines) > 0 {
		if addrs := resolveBootstrapAddrs(lines, log); len(addrs) > 0 {
			log.Info("connecting to network", "source", "peers.cache", "peers", len(addrs))
			if tryBootstrap(ctx, h, addrs, log, "peers.cache") {
				return true
			}
		}
	} else if err != nil {
		log.Debug("peers.cache", "err", err)
	}

	if len(cfg.Bootstrap) > 0 {
		if addrs := resolveBootstrapAddrs(cfg.Bootstrap, log); len(addrs) > 0 {
			log.Info("connecting to network", "source", "config", "peers", len(addrs))
			if tryBootstrap(ctx, h, addrs, log, "config") {
				return true
			}
		}
	}

	log.Info("looking up bootstrap peers")
	if txt := lookupBootstrapTXT(dnsBootstrapName); len(txt) > 0 {
		if addrs := resolveBootstrapAddrs(txt, log); len(addrs) > 0 {
			log.Info("connecting to network", "source", "dns", "peers", len(addrs))
			if tryBootstrap(ctx, h, addrs, log, "dns_txt") {
				return true
			}
		}
	}

	return false
}

// deriveSignalURL returns a signal base URL from trusted infrastructure sources
// only: config.Bootstrap or DNS TXT records. peers.cache is intentionally
// excluded because it contains arbitrary DHT peers, not signaling hubs.
func deriveSignalURL(cfg *config.Config, log *slog.Logger) string {
	if hp := firstBootstrapHostPort(cfg.Bootstrap); hp != "" {
		if u, err := signaling.DeriveSignalBaseFromHostPort(hp); err == nil {
			log.Debug("signal url derived", "source", "config", "url", u)
			return u
		}
	}
	if txt := lookupBootstrapTXT(dnsBootstrapName); len(txt) > 0 {
		if hp := firstBootstrapHostPort(txt); hp != "" {
			if u, err := signaling.DeriveSignalBaseFromHostPort(hp); err == nil {
				log.Debug("signal url derived", "source", "dns", "url", u)
				return u
			}
		}
	}
	return ""
}

func firstBootstrapHostPort(lines []string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func addrToHostPort(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		if v == nil || v.Port == 0 {
			return ""
		}
		return v.String()
	default:
		return a.String()
	}
}

func resolveBootstrapAddrs(hostports []string, log *slog.Logger) []net.Addr {
	var out []net.Addr
	for _, s := range hostports {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		a, err := net.ResolveUDPAddr("udp4", s)
		if err != nil {
			log.Debug("bootstrap resolve skip", "addr", s, "err", err)
			continue
		}
		out = append(out, a)
	}
	return out
}

func tryBootstrap(ctx context.Context, h *host.Host, addrs []net.Addr, log *slog.Logger, src string) bool {
	if len(addrs) == 0 {
		return false
	}
	bctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := h.Node().BootstrapAddrs(bctx, addrs); err != nil {
		log.Warn("bootstrap failed", "source", src, "err", err)
		return false
	}
	obctx, ocancel := context.WithTimeout(ctx, 10*time.Second)
	defer ocancel()
	h.ObserveFromPeers(obctx, addrs)

	peers := len(h.Node().BootstrapCandidateAddrs(10))
	minAgree := h.Sense().MinAgreeing()
	if peers > 0 && peers < minAgree {
		h.Sense().SetMinAgreeing(peers)
		log.Info("natsense threshold adjusted", "peers", peers, "new_min", peers)
	}

	log.Info("bootstrap ok", "source", src)
	return true
}

func lookupBootstrapTXT(name string) []string {
	txts, err := net.LookupTXT(name)
	if err != nil {
		return nil
	}
	var out []string
	for _, block := range txts {
		for _, part := range strings.FieldsFunc(block, func(r rune) bool {
			return r == ',' || r == ';' || r == ' '
		}) {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
