// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al/cmd/a2ald/internal/peerscache"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"log/slog"
)

const dnsBootstrapName = "_a2al-bootstrap.a2al.org"

func runBootstrapChain(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger) {
	cachePath := filepath.Join(dataDir, "peers.cache")
	if lines, err := peerscache.Load(cachePath); err == nil && len(lines) > 0 {
		if addrs := resolveBootstrapAddrs(lines, log); len(addrs) > 0 {
			if tryBootstrap(ctx, h, addrs, log, "peers.cache") {
				return
			}
		}
	} else if err != nil {
		log.Debug("peers.cache", "err", err)
	}

	if len(cfg.Bootstrap) > 0 {
		addrs := resolveBootstrapAddrs(cfg.Bootstrap, log)
		if len(addrs) > 0 && tryBootstrap(ctx, h, addrs, log, "config") {
			return
		}
	}

	if txt := lookupBootstrapTXT(dnsBootstrapName); len(txt) > 0 {
		addrs := resolveBootstrapAddrs(txt, log)
		if len(addrs) > 0 && tryBootstrap(ctx, h, addrs, log, "dns_txt") {
			return
		}
	}
}

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
		log.Debug("bootstrap failed", "source", src, "err", err)
		return false
	}
	obctx, ocancel := context.WithTimeout(ctx, 10*time.Second)
	defer ocancel()
	h.ObserveFromPeers(obctx, addrs)
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
