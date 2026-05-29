// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/peerscache"
	"github.com/a2al/a2al/internal/retry"
	"github.com/a2al/a2al/signaling"
)

const dnsBootstrapName = "_a2al-bootstrap.a2al.org"

// coldStartRetry constants bound the background retry of trusted bootstrap
// seeds during a cold start: re-ping each failed seed every interval, give up
// joining after the window, accept standalone operation.
//
// coldStartPingTimeout must exceed rpcAttemptTimeout (5 s) so that
// sendAndWait's per-attempt deadline is not prematurely cancelled by the outer
// context — otherwise no internal retry can ever fire.
const (
	coldStartRetryInterval = 10 * time.Second
	coldStartRetryWindow   = 60 * time.Second
	coldStartPingTimeout   = 6 * time.Second // > rpcAttemptTimeout (5 s)
)

// runBootstrapChain joins the DHT and sets ICE signal hub candidates.
//
// Signal hub URLs are derived and installed regardless of whether the DHT join
// succeeds: the signal TCP path is independent of the DHT UDP path, so a node
// that is standalone on DHT can still send/receive ICE sessions via signal hubs.
//
// Returns true if at least one DHT peer was contacted.
func runBootstrapChain(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger, bm *beaconManager) bool {
	joined := bootstrapDHT(ctx, h, cfg, dataDir, log, bm)
	// Derive and install signal hub URLs unconditionally so runICEListener (already
	// running) can connect to hubs even when the DHT join failed.
	if urls := deriveSignalURLs(cfg, log); len(urls) > 0 {
		h.SetBootstrapHubURLs(urls)
	}
	if !joined {
		log.Warn("network connectivity issue; entering standalone mode, retrying to join in background")
	}
	return joined
}

// bootstrapDHT joins the DHT using persisted peers and trusted seeds.
//
// Address sources and their priority:
//
//	peers.cache  — fast local snapshot; always tried first.
//	cfg.Bootstrap — operator-controlled seeds (private deployments); tried in parallel
//	               with peers.cache when set; skips public DNS (full operator control).
//	DNS TXT      — public infra; resolved in parallel with peers.cache when cfg.Bootstrap
//	               is empty; heals stale caches without requiring a config change.
//	beacon       — last resort when all other sources fail.
//
// All sources (except beacon) are tried concurrently; the first successful contact
// starts FindNode immediately without waiting for slower seeds.
func bootstrapDHT(ctx context.Context, h *host.Host, cfg *config.Config, dataDir string, log *slog.Logger, bm *beaconManager) bool {
	// Collect seeds: peers.cache is always included; the second source is either
	// cfg.Bootstrap (private) or a live DNS lookup (public), both fetched in parallel.
	var cacheAddrs []net.Addr
	cachePath := filepath.Join(dataDir, "peers.cache")
	if lines, err := peerscache.Load(cachePath); err == nil && len(lines) > 0 {
		cacheAddrs = resolveBootstrapAddrs(lines, log)
	} else if err != nil {
		log.Debug("peers.cache", "err", err)
	}

	// Fetch the second address source concurrently with peers.cache resolution above.
	var secondTXT []string // raw hostport strings; needed for DNS reuse in deriveSignalURLs
	type secondResult struct {
		addrs []net.Addr
		txt   []string // set only for the DNS path
	}
	secondCh := make(chan secondResult, 1)
	if len(cfg.Bootstrap) > 0 {
		// Private deployment: use config seeds directly, no DNS.
		go func() {
			addrs := resolveBootstrapAddrs(cfg.Bootstrap, log)
			addrs = filterByNodeID(ctx, h, addrs, cfg.BootstrapNodeIDs, log)
			secondCh <- secondResult{addrs: addrs}
		}()
	} else {
		// Public network: resolve DNS TXT in the background while peers.cache pings proceed.
		go func() {
			txt := lookupBootstrapTXT(dnsBootstrapName)
			addrs := resolveBootstrapAddrs(txt, log)
			addrs = filterByNodeID(ctx, h, addrs, cfg.BootstrapNodeIDs, log)
			secondCh <- secondResult{addrs: addrs, txt: txt}
		}()
	}

	// Dedup helper: merges addr slices, skipping duplicates by string key.
	dedup := func(a, b []net.Addr) []net.Addr {
		seen := make(map[string]struct{}, len(a)+len(b))
		out := make([]net.Addr, 0, len(a)+len(b))
		for _, addr := range append(a, b...) {
			if k := addr.String(); k != "" {
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					out = append(out, addr)
				}
			}
		}
		return out
	}

	second := <-secondCh
	secondTXT = second.txt

	// Merge both sources and ping them all in one parallel batch.
	allAddrs := dedup(cacheAddrs, second.addrs)
	var ok bool
	if len(allAddrs) > 0 {
		src := "peers.cache+dns"
		if len(cfg.Bootstrap) > 0 {
			src = "peers.cache+config"
		}
		log.Info("connecting to network", "source", src, "peers", len(allAddrs))
		if tryBootstrap(ctx, h, allAddrs, log, src) {
			ok = true
		}
	}

	// Store DNS TXT result for reuse by deriveSignalURLs so we avoid a second lookup.
	if len(secondTXT) > 0 {
		storeDNSTXTResult(secondTXT)
	}

	// Last resort: public beacon infrastructure — only when all other sources failed
	// AND no operator-supplied bootstrap is configured. A private deployment that
	// explicitly set cfg.Bootstrap must not silently widen to public infra when its
	// seeds are temporarily unreachable.
	if !ok && len(cfg.Bootstrap) == 0 {
		if beaconAddrs := bm.refreshAddrs(); len(beaconAddrs) > 0 {
			log.Info("connecting to network", "source", "aux_dht_bootstrap")
			if tryBootstrap(ctx, h, beaconAddrs, log, "aux_dht_bootstrap") {
				ok = true
			}
		}
	}

	return ok
}

// dnsTXTCache holds the most recent DNS TXT bootstrap result so deriveSignalURLs
// can reuse it without issuing a second DNS query during the same startup.
var dnsTXTCacheMu sync.Mutex
var dnsTXTCached []string

func storeDNSTXTResult(txt []string) {
	dnsTXTCacheMu.Lock()
	dnsTXTCached = txt
	dnsTXTCacheMu.Unlock()
}

func loadDNSTXTResult() []string {
	dnsTXTCacheMu.Lock()
	defer dnsTXTCacheMu.Unlock()
	return dnsTXTCached
}

// maxSignalCandidates caps the number of bootstrap-derived signal hub candidates.
// This bounds the subscriber goroutines and the Signals[] list in DHT records.
const maxSignalCandidates = 4

// deriveSignalURLs returns signal hub base URLs from trusted infrastructure sources
// only (config.Bootstrap or DNS TXT records). peers.cache is intentionally excluded
// because it contains arbitrary DHT peers, not signaling hubs. Returns up to
// maxSignalCandidates unique URLs, preserving bootstrap list order.
//
// When cfg.Bootstrap is empty, the DNS TXT result cached by bootstrapDHT is reused
// to avoid a second DNS round-trip during the same startup sequence.
func deriveSignalURLs(cfg *config.Config, log *slog.Logger) []string {
	var out []string
	seen := make(map[string]struct{})

	addHostPorts := func(lines []string, source string) {
		for _, line := range lines {
			if hp := strings.TrimSpace(line); hp != "" {
				if u, err := signaling.DeriveSignalBaseFromHostPort(hp); err == nil {
					if _, dup := seen[u]; !dup {
						seen[u] = struct{}{}
						log.Debug("signal url derived", "source", source, "url", u)
						out = append(out, u)
						if len(out) >= maxSignalCandidates {
							return
						}
					}
				}
			}
		}
	}

	if len(cfg.Bootstrap) > 0 {
		addHostPorts(cfg.Bootstrap, "config")
	} else {
		// Reuse the DNS TXT result from bootstrapDHT if available; fall back to a
		// fresh lookup only when called outside the normal startup sequence.
		txt := loadDNSTXTResult()
		if len(txt) == 0 {
			txt = lookupBootstrapTXT(dnsBootstrapName)
		}
		if len(txt) > 0 {
			addHostPorts(txt, "dns")
		}
	}
	return out
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
		// Use "udp" (not "udp4") so that literal IPv6 bootstrap addresses
		// (e.g. "[2001:db8::1]:4121") are resolved correctly.
		a, err := net.ResolveUDPAddr("udp", s)
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
	// Observed_addr is already recorded in PingIdentity → notifyObserved on
	// each successful bootstrap ping; a second ObserveFromPeers round would
	// re-ping every seed including known-failed addresses.

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
		if urls := deriveSignalURLs(d.cfg, d.log); len(urls) > 0 {
			d.h.SetBootstrapHubURLs(urls)
		}
		d.h.SetRoutingHubCandidates(d.h.DeriveRoutingHubURLs(maxSignalCandidates))
		d.log.Info("bootstrap recovery succeeded")
		// Trigger a cascade so observe/probe/publish run with the newly joined
		// peers. guard tick picks this up within guardTickPeriod (5 s).
		select {
		case d.netChangeNotify <- struct{}{}:
		default:
		}
	}
}

// trustedSeedAddrs returns the set of trusted bootstrap seed addresses to retry
// during a cold start. Only infrastructure-controlled sources are included:
// config seeds, DNS TXT, or beacon. peers.cache is intentionally excluded because
// it is a snapshot of the routing table (may contain unverified hearsay addresses)
// and is only suitable for the one-shot fast-start attempt in bootstrapDHT.
func trustedSeedAddrs(cfg *config.Config, bm *beaconManager, log *slog.Logger) []net.Addr {
	var out []net.Addr
	seen := make(map[string]struct{})
	add := func(addrs []net.Addr) {
		for _, a := range addrs {
			k := a.String()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, a)
		}
	}

	if len(cfg.Bootstrap) > 0 {
		add(resolveBootstrapAddrs(cfg.Bootstrap, log))
		return out // operator-controlled seeds: do not widen to public DNS/beacon
	}
	if txt := lookupBootstrapTXT(dnsBootstrapName); len(txt) > 0 {
		add(resolveBootstrapAddrs(txt, log))
	}
	if len(out) == 0 && bm != nil {
		add(bm.refreshAddrs())
	}
	return out
}

// startColdStartRetry re-pings trusted bootstrap seeds that are not yet reachable
// every coldStartRetryInterval for up to coldStartRetryWindow, then accepts
// standalone operation. It runs whether or not the initial bootstrap succeeded:
// seeds that are already reachable resolve on their first probe and drop out, so
// only genuinely-failed trusted seeds keep being retried.
//
// On the transition from "not joined" to "joined" it applies hub URLs and fires
// netChangeNotify so the main loop runs a republish cascade. Must be called in a
// goroutine; returns when every seed has resolved or the window/ctx closes.
func (d *Daemon) startColdStartRetry(ctx context.Context, alreadyJoined bool) {
	// A strict NodeID allowlist requires verifying each seed's identity before
	// admitting it; that belongs to the verified maybeRebootstrap path. Skip the
	// fast plain-ping retry here to avoid admitting unverified addresses.
	if len(d.cfg.BootstrapNodeIDs) > 0 {
		return
	}
	seeds := trustedSeedAddrs(d.cfg, d.beacon, d.log)
	if len(seeds) == 0 {
		return
	}
	byKey := make(map[string]net.Addr, len(seeds))
	for _, a := range seeds {
		byKey[a.String()] = a
	}

	var joined atomic.Bool
	joined.Store(alreadyJoined)
	var once sync.Once

	attempt := func(actx context.Context, key string) retry.Outcome {
		addr := byKey[key]
		pctx, cancel := context.WithTimeout(actx, coldStartPingTimeout)
		_, err := d.h.Node().PingIdentity(pctx, addr)
		cancel()
		if err != nil {
			return retry.Again
		}
		// Reachable: PingIdentity has already added this peer to the routing
		// table. If we weren't joined before, fire the hub-URL setup and the
		// netChangeNotify cascade exactly once. When alreadyJoined=true the
		// initial bootstrap already applied URLs; we just fill the routing table.
		joined.Store(true)
		if !alreadyJoined {
			once.Do(func() {
				if urls := deriveSignalURLs(d.cfg, d.log); len(urls) > 0 {
					d.h.SetBootstrapHubURLs(urls)
				}
				d.h.SetRoutingHubCandidates(d.h.DeriveRoutingHubURLs(maxSignalCandidates))
				d.log.Info("bootstrap succeeded after cold-start retry")
				select {
				case d.netChangeNotify <- struct{}{}:
				default:
				}
			})
		}
		return retry.Done
	}

	wctx, cancel := context.WithTimeout(ctx, coldStartRetryWindow)
	defer cancel()
	// Factor 1 keeps a constant interval; ctx bounds the window, so no per-key
	// give-up policy is needed.
	sched := retry.New[string](retry.Policy{Base: coldStartRetryInterval, Factor: 1}, attempt, nil)
	for k := range byKey {
		sched.Add(k)
	}
	sched.Run(wctx)

	if !joined.Load() {
		d.log.Warn("standalone mode: no peers reachable after retry window; operating standalone")
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
