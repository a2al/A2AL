// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
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
func runBootstrapChain(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger, bm *beaconManager) string {
	if !bootstrapDHT(ctx, h, cfg, dataDir, log, bm) {
		log.Info("no bootstrap peers reachable, starting as standalone node")
		return ""
	}
	return deriveSignalURL(cfg, log)
}

// bootstrapDHT joins the DHT using persisted peers, then optional config seeds,
// then optional DNS TXT seeds.
//
// If cfg.Bootstrap is non-empty, the user supplied their own seeds: we try
// peers.cache then config only — no public DNS lookup (full operator control).
//
// If cfg.Bootstrap is empty, after peers.cache we always attempt DNS TXT once
// when records exist: this heals splits and corrects a stale peers.cache without
// requiring a config field.
func bootstrapDHT(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger, bm *beaconManager) bool {
	var ok bool

	cachePath := filepath.Join(dataDir, "peers.cache")
	if lines, err := peerscache.Load(cachePath); err == nil && len(lines) > 0 {
		if addrs := resolveBootstrapAddrs(lines, log); len(addrs) > 0 {
			log.Info("connecting to network", "source", "peers.cache", "peers", len(addrs))
			if tryBootstrap(ctx, h, addrs, log, "peers.cache") {
				ok = true
			}
		}
	} else if err != nil {
		log.Debug("peers.cache", "err", err)
	}

	if len(cfg.Bootstrap) > 0 {
		if addrs := resolveBootstrapAddrs(cfg.Bootstrap, log); len(addrs) > 0 {
			addrs = filterByNodeID(ctx, h, addrs, cfg.BootstrapNodeIDs, log)
			if len(addrs) > 0 {
				log.Info("connecting to network", "source", "config", "peers", len(addrs))
				if tryBootstrap(ctx, h, addrs, log, "config") {
					ok = true
				}
			}
		}
		return ok
	}

	log.Info("looking up public peers (bootstrap)")
	if txt := lookupBootstrapTXT(dnsBootstrapName); len(txt) > 0 {
		if addrs := resolveBootstrapAddrs(txt, log); len(addrs) > 0 {
			addrs = filterByNodeID(ctx, h, addrs, cfg.BootstrapNodeIDs, log)
			if len(addrs) > 0 {
				log.Info("connecting to network", "source", "dns", "peers", len(addrs))
				if tryBootstrap(ctx, h, addrs, log, "dns_txt") {
					ok = true
				}
			}
		}
	}

	// Last resort: infrastructure DNS TXT for well-known DHT peer addresses (auxiliary
	// read/store and this bootstrap attempt) — only when all earlier steps failed.
	if !ok {
		if beaconAddrs := bm.refreshAddrs(); len(beaconAddrs) > 0 {
			log.Info("connecting to network", "source", "aux_dht_bootstrap")
			if tryBootstrap(ctx, h, beaconAddrs, log, "aux_dht_bootstrap") {
				ok = true
			}
		}
	}

	return ok
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

// rebootstrapMinGap limits how often we retry bootstrapDHT when the routing
// table has no candidates (recovery path).
const rebootstrapMinGap = 5 * time.Minute

// maybeRebootstrap runs bootstrapDHT when there are no known DHT peers, subject
// to rebootstrapMinGap. Used after network changes and on a long-period tick.
func (d *Daemon) maybeRebootstrap(ctx context.Context) {
	if d.testMaybeRebootstrapFn != nil {
		d.testMaybeRebootstrapFn(ctx)
		return
	}
	if len(d.h.Node().BootstrapCandidateAddrs(1)) > 0 {
		return
	}
	d.rebootstrapMu.Lock()
	now := d.now()
	if !d.lastRebootstrapAt.IsZero() && now.Sub(d.lastRebootstrapAt) < rebootstrapMinGap {
		d.rebootstrapMu.Unlock()
		return
	}
	d.lastRebootstrapAt = now
	d.rebootstrapMu.Unlock()

	if bootstrapDHT(ctx, d.h, d.cfg, d.dataDir, d.log, d.beacon) {
		if u := deriveSignalURL(d.cfg, d.log); u != "" {
			d.h.SetDerivedICESignalURL(u)
		}
		d.log.Info("bootstrap recovery succeeded")
		// Trigger a cascade so observe/probe/publish run with the newly joined
		// peers. guard tick picks this up within guardTickPeriod (5 s).
		select {
		case d.netChangeNotify <- struct{}{}:
		default:
		}
	}
}

// filterByNodeID returns the subset of addrs whose NodeID (obtained via PING)
// is in allowedIDs. When allowedIDs is empty, all addrs pass through unchanged.
func filterByNodeID(ctx context.Context, h *host.Host, addrs []net.Addr, allowedIDs []string, log *slog.Logger) []net.Addr {
	if len(allowedIDs) == 0 {
		return addrs
	}
	allowed := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
	}
	var out []net.Addr
	for _, addr := range addrs {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		id, err := h.Node().PingIdentity(pctx, addr)
		cancel()
		if err != nil {
			log.Debug("bootstrap: NodeID ping failed, skipping", "addr", addr, "err", err)
			continue
		}
		nidHex := hex.EncodeToString(id.NodeID[:])
		if _, ok := allowed[nidHex]; ok {
			out = append(out, addr)
		} else {
			log.Warn("bootstrap: NodeID not in allowlist, rejecting", "addr", addr, "node_id", nidHex)
		}
	}
	return out
}
