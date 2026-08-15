// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
)

const (
	beaconDNSAddr      = "_a2al-bootstrap.tngld.net"
	beaconMaxStoreKeys = 5_000_000

	// beaconMultiServiceSizeThreshold is the estimated network size above which
	// multi-service discover queries skip the optional DNS-announced infrastructure
	// read path. Below this the DHT may not have enough density to cover all keys; above
	// it the intersection can be computed reliably from DHT results alone.
	beaconMultiServiceSizeThreshold = 500

	// beaconResolveContactThreshold is the minimum number of distinct peers that
	// must have replied (real response, not timeout) during a FIND_VALUE for the
	// "no record" result to be treated as authoritative.
	//
	// Value = routing.K (16) + 4 convergence-path buffer = 20.
	//   - K=16 covers the theoretical K-closest neighbourhood.
	//   - +4 accounts for the intermediate nodes contacted along the iterative
	//     convergence path that are not among the final K-closest but still
	//     confirmed absence.  This margin also guards against the rare case where
	//     a few of the K-closest nodes were unreachable (timeout) and their slots
	//     were filled by slightly further nodes.
	// Below this count the query was likely cut short (sparse routing table or
	// early context cancellation) and beacon fallback is still attempted.
	beaconResolveContactThreshold = 20

	// beaconPerPeerTimeout is the per-beacon deadline for a single FindValue RPC.
	// Keeping it short (3 s) prevents an offline beacon from stalling the fallback
	// iteration; the caller's context provides the outer bound.
	beaconPerPeerTimeout = 3 * time.Second
)

// beaconManager handles supplemental DHT store fan-out and last-resort read fallback
// against a dedicated DNS TXT name (well-known multi-address list, same origin as
// cold-start bootstrap when no other path succeeds).
type beaconManager struct {
	mu        sync.RWMutex
	addrs     []net.Addr
	lastDNSAt time.Time
	dnsOnce   sync.Mutex // serialises concurrent refreshes

	active    atomic.Bool
	storeSent atomic.Uint64
	queryHits atomic.Uint64

	node *dht.Node
	cfg  *config.Config
	log  *slog.Logger
}

func newBeaconManager(node *dht.Node, cfg *config.Config, log *slog.Logger) *beaconManager {
	return &beaconManager{node: node, cfg: cfg, log: log}
}

// start initialises the manager. Call once after DHT node is running.
// agentKeysFn returns the current set of agent keys for the initial store push.
func (b *beaconManager) start(ctx context.Context, agentKeysFn func() []a2al.NodeID) {
	if b.cfg.BeaconMode {
		b.active.Store(true)
		b.node.SetMaxStoreKeys(beaconMaxStoreKeys)
		b.node.SetPassiveRouting(true)
		b.log.Info("aux-dht: operator-configured high-capacity passive local store active")
	}
	go func() {
		addrs := b.refreshAddrs()
		if len(addrs) == 0 {
			return
		}
		if !b.active.Load() {
			b.trySelfIdentify(addrs)
		}
		b.StoreAll(ctx, agentKeysFn())
	}()
}

// trySelfIdentify checks whether this node's public IP (v4 or v6) appears in
// the well-known beacon address list. If so, enables the high-capacity local
// store path (same behaviour as the operator high-capacity role in config).
//
// Hairpin detection and beacon self-identify are intentionally separate
// concerns: SetSelfExtIP covers v4 hairpin detection (NAT peers); this
// function covers beacon self-identify for both v4 and v6 GUA nodes.
func (b *beaconManager) trySelfIdentify(addrs []net.Addr) {
	selfIPv4 := b.node.SelfExtIP()
	selfIPv6 := b.node.SelfExtIPv6()
	if selfIPv4 == nil && selfIPv6 == nil {
		return
	}
	for _, a := range addrs {
		udp, ok := a.(*net.UDPAddr)
		if !ok {
			continue
		}
		match := (selfIPv4 != nil && selfIPv4.Equal(udp.IP)) ||
			(selfIPv6 != nil && selfIPv6.Equal(udp.IP))
		if match {
			b.active.Store(true)
			b.node.SetMaxStoreKeys(beaconMaxStoreKeys)
			b.node.SetPassiveRouting(true)
			b.log.Info("aux-dht: public IP in well-known DNS TXT, expanded local store")
			return
		}
	}
}

// RefreshAndStore re-resolves DNS (if stale) then fires StoreAll. Called each
// republish tick so the cached well-known address list stays current without an extra timer.
func (b *beaconManager) RefreshAndStore(ctx context.Context, keys []a2al.NodeID) {
	addrs := b.refreshAddrs()
	if len(addrs) == 0 {
		return
	}
	b.StoreAll(ctx, keys)
}

// Addrs returns the current well-known peer addresses from the last DNS resolution.
func (b *beaconManager) Addrs() []net.Addr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.addrs
}

// shuffledAddrs returns the well-known address set sorted by ascending RTT
// (fastest first), excluding this node's own address. Addresses for which no
// RTT has been measured yet (never contacted) are appended after the known-RTT set.
// This gives a deterministic, performance-based preference without introducing
// extra random state, and naturally spreads load when the top-ranked address is
// consistently responsive.
func (b *beaconManager) shuffledAddrs() []net.Addr {
	selfIPv4 := b.node.SelfExtIP()
	selfIPv6 := b.node.SelfExtIPv6()
	b.mu.RLock()
	raw := b.addrs
	b.mu.RUnlock()

	var known, unknown []net.Addr
	for _, a := range raw {
		if udp, ok := a.(*net.UDPAddr); ok {
			if (selfIPv4 != nil && selfIPv4.Equal(udp.IP)) ||
				(selfIPv6 != nil && selfIPv6.Equal(udp.IP)) {
				continue
			}
		}
		if b.node.PeerRTT(a) > 0 {
			known = append(known, a)
		} else {
			unknown = append(unknown, a)
		}
	}
	sort.Slice(known, func(i, j int) bool {
		return b.node.PeerRTT(known[i]) < b.node.PeerRTT(known[j])
	})
	return append(known, unknown...)
}

// StoreAll issues fire-and-forget STORE to every listed well-known address for each key,
// skipping any address that belongs to this node.
// When this process runs the high-capacity local-store role, it no-ops: every
// other node already issues StoreAt to the full set, so extra copies would only add traffic.
func (b *beaconManager) StoreAll(ctx context.Context, keys []a2al.NodeID) {
	if b.active.Load() {
		// This instance participates in the high-capacity store role: peers
		// already replicate here via StoreAt; nothing useful to push.
		return
	}
	addrs := b.shuffledAddrs()
	if len(addrs) == 0 {
		return
	}
	now := time.Now()
	for _, key := range keys {
		recs := b.node.LocalStoreGet(key, 0)
		for _, rec := range recs {
			if protocol.VerifySignedRecord(rec, now) != nil {
				continue
			}
			for _, addr := range addrs {
				a := addr
				r := rec
				k := key
				go func() {
					sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					stored, peerID, meta, _, err := b.node.StoreAt(sctx, a, k, r)
					dial := meta.DialAddr()
					if dial == nil {
						dial = a
					}
					if err != nil {
						b.log.Debug("aux-dht store failed", "addr", a, "dial", dial, "path", meta.Reason(), "key", hex.EncodeToString(k[:4]), "err", err)
						return
					}
					if !stored {
						b.log.Debug("aux-dht store rejected", "addr", a, "dial", dial, "path", meta.Reason(), "key", hex.EncodeToString(k[:4]))
						return
					}
					if peerID != (a2al.NodeID{}) {
						if ua, ok := a.(*net.UDPAddr); ok {
							b.node.BindPeerAnchor(peerID, ua)
						}
					}
					b.log.Debug("aux-dht store ok", "addr", a, "dial", dial, "path", meta.Reason(), "peer", peerID, "key", hex.EncodeToString(k[:4]))
				}()
				b.storeSent.Add(1)
			}
		}
	}
}

// FindRecords walks the well-known address set and returns records from the
// first beacon that supplies a non-empty response.
//
// Load distribution: the iteration start is derived from the first two bytes of
// key, so different keys naturally spread across different beacons while RTT
// ordering (from shuffledAddrs) is still preserved within the rotation.  Same
// key always picks the same primary beacon (cache-friendly).
//
// Availability: each beacon is contacted with a short per-peer timeout so that
// offline beacons cannot stall the fallback path.  Empty responses are not
// treated as authoritative; iteration continues until a non-empty result is
// found or all beacons are exhausted.
func (b *beaconManager) FindRecords(ctx context.Context, key a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	addrs := b.shuffledAddrs()
	if len(addrs) == 0 {
		return nil, nil
	}
	// Rotate the RTT-sorted list by a key-derived offset for load distribution.
	// binary.BigEndian.Uint16 gives a stable, cheap hash of the key prefix.
	if n := len(addrs); n > 1 {
		offset := int(binary.BigEndian.Uint16(key[:2])) % n
		addrs = append(addrs[offset:], addrs[:offset]...)
	}
	now := time.Now()
	seen := map[string]struct{}{}
	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		// Per-beacon timeout: avoid stalling on an offline node.
		bctx, bcancel := context.WithTimeout(ctx, beaconPerPeerTimeout)
		recs, _, err := b.node.FindValueWithNodes(bctx, addr, key, recType, false)
		bcancel()
		if err != nil {
			b.log.Debug("aux-dht find", "addr", addr, "err", err)
			continue // offline / unreachable; try next beacon
		}
		var out []protocol.SignedRecord
		for _, r := range recs {
			if protocol.VerifySignedRecord(r, now) != nil {
				continue
			}
			dk := beaconDedupeKey(r)
			if _, ok := seen[dk]; ok {
				continue
			}
			seen[dk] = struct{}{}
			out = append(out, r)
		}
		if len(out) > 0 {
			b.queryHits.Add(1)
			return out, nil // found records – return immediately
		}
		// Empty response from this beacon (does not hold this key); try next.
	}
	return nil, nil
}

// Stats returns a map for merging into /debug/stats. Returns nil when this
// process is not on the high-capacity auxiliary path, so regular nodes see no
// extra keys in the response.
func (b *beaconManager) Stats() map[string]any {
	if !b.active.Load() {
		return nil
	}
	b.mu.RLock()
	addrStrs := make([]string, len(b.addrs))
	for i, a := range b.addrs {
		addrStrs[i] = a.String()
	}
	b.mu.RUnlock()
	out := map[string]any{
		"beacon_store_received":   b.node.StoreRxCount(),
		"beacon_findvalue_served": b.node.FindValueServedCount(),
		"beacon_mode":             true,
	}
	if len(addrStrs) > 0 {
		out["beacon_addrs"] = addrStrs
	}
	return out
}

// refreshAddrs re-resolves DNS if the cache is stale (older than republish period).
// The DNS lookup runs outside the mutex to avoid blocking concurrent readers.
func (b *beaconManager) refreshAddrs() []net.Addr {
	// Fast path: cache is still fresh.
	b.mu.RLock()
	if b.lastDNSAt != (time.Time{}) && time.Since(b.lastDNSAt) < republishPeriod {
		addrs := b.addrs
		b.mu.RUnlock()
		return addrs
	}
	b.mu.RUnlock()

	// Serialise refreshes so concurrent callers don't all hit DNS simultaneously.
	b.dnsOnce.Lock()
	defer b.dnsOnce.Unlock()

	// Re-check under the serialisation lock; another goroutine may have refreshed.
	b.mu.RLock()
	if b.lastDNSAt != (time.Time{}) && time.Since(b.lastDNSAt) < republishPeriod {
		addrs := b.addrs
		b.mu.RUnlock()
		return addrs
	}
	b.mu.RUnlock()

	// DNS lookup outside any lock.
	txts, err := net.LookupTXT(beaconDNSAddr)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// NXDOMAIN: record actively removed - clear cached well-known addresses.
			b.mu.Lock()
			b.addrs = nil
			b.lastDNSAt = time.Now()
			b.mu.Unlock()
			return nil
		}
		// Transient network error: preserve existing cache, don't update timestamp.
		b.mu.RLock()
		addrs := b.addrs
		b.mu.RUnlock()
		return addrs
	}

	var flat []string
	for _, block := range txts {
		for _, part := range strings.FieldsFunc(block, func(r rune) bool {
			return r == ',' || r == ';' || r == ' '
		}) {
			if p := strings.TrimSpace(part); p != "" {
				flat = append(flat, p)
			}
		}
	}
	if len(flat) == 0 {
		b.mu.Lock()
		b.addrs = nil
		b.lastDNSAt = time.Now()
		b.mu.Unlock()
		return nil
	}
	addrs := resolveBootstrapAddrs(flat, b.log)
	b.mu.Lock()
	b.addrs = addrs
	b.lastDNSAt = time.Now()
	b.mu.Unlock()
	return addrs
}

// beaconDedupeKey returns a string key for deduplicating SignedRecords.
// Mailbox records are keyed by sender pubkey + seq so distinct messages from
// the same sender are preserved; all other types are keyed by address + type + pubkey.
func beaconDedupeKey(r protocol.SignedRecord) string {
	if r.RecType == protocol.RecTypeMailbox {
		return "mb:" + hex.EncodeToString(r.Pubkey) + ":" + hex.EncodeToString(r.Payload[:min(32, len(r.Payload))])
	}
	return hex.EncodeToString(r.Address) + ":" + string([]byte{r.RecType}) + ":" + hex.EncodeToString(r.Pubkey)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// resolveTracked runs an iterative FIND_VALUE for aid and returns the endpoint
// record together with the number of distinct DHT peers contacted during the
// query.  The contact count is used by beaconShouldFallbackForResolve to decide
// whether the query was thorough enough to treat "no record" as authoritative.
func (d *Daemon) resolveTracked(ctx context.Context, aid a2al.Address) (*protocol.EndpointRecord, int, error) {
	q := dht.NewQuery(d.h.Node())
	er, err := q.Resolve(ctx, a2al.NodeIDFromAddress(aid))
	return er, q.NodesContacted(), err
}

// beaconShouldFallbackForResolve reports whether a failed resolve call warrants
// a beacon fallback, given the error and the number of distinct nodes that were
// contacted during the iterative query.
//
// Design for "DHT sufficient":
//   - ErrNoEndpoint means the query traversed K-closest nodes and found nothing.
//     That result is authoritative only when contacted ≥ beaconResolveContactThreshold
//     (20 = K+4): if 20 or more distinct peers replied (not just timed out) with
//     no record, the target's neighbourhood was covered and repeating the question
//     to a beacon adds nothing.
//   - contacted < 20 means the query was cut short (sparse routing table,
//     context deadline, etc.) — beacon fallback is appropriate.
//   - Any other error (timeout, network error) means the query was incomplete;
//     beacon is always tried regardless of contact count.
func (d *Daemon) beaconShouldFallbackForResolve(err error, contacted int) bool {
	if !errors.Is(err, dht.ErrNoEndpoint) {
		return true // incomplete query; always try beacon
	}
	return contacted < beaconResolveContactThreshold
}

// resolveFromBeacon resolves an endpoint record through the optional DNS-announced
// read path, using the well-known address set and the same lookup as FindRecords.
func (d *Daemon) resolveFromBeacon(ctx context.Context, aid a2al.Address) (*protocol.EndpointRecord, error) {
	key := a2al.NodeIDFromAddress(aid)
	recs, err := d.beacon.FindRecords(ctx, key, protocol.RecTypeEndpoint)
	if err != nil || len(recs) == 0 {
		return nil, dht.ErrNoEndpoint
	}
	now := time.Now()
	for _, r := range recs {
		if r.RecType != protocol.RecTypeEndpoint {
			continue
		}
		if protocol.VerifySignedRecord(r, now) != nil {
			continue
		}
		er, err := protocol.ParseEndpointRecord(r)
		if err == nil {
			return &er, nil
		}
	}
	return nil, dht.ErrNoEndpoint
}

// discoverFromBeacon issues multi-service find traffic against the first
// responsive well-known address in RTT order (shuffledAddrs) and returns the
// AID intersection. The listed peers are targets of the same store fan-out, so
// one responder is enough; the ordering still spreads work across the set.
//
// When the estimated network size exceeds beaconMultiServiceSizeThreshold and
// len(services) > 1, the DHT is dense enough to serve the intersection reliably,
// so the infrastructure read path is skipped to avoid biasing the result mix.
func (d *Daemon) discoverFromBeacon(ctx context.Context, services []string) []protocol.TopicEntry {
	if len(services) == 0 {
		return nil
	}
	if len(services) > 1 {
		est, conf := d.beacon.node.EstimatedNetworkSizeFiltered(time.Now().Add(-30 * time.Minute))
		if est >= beaconMultiServiceSizeThreshold && conf >= 0.6 {
			return nil
		}
	}

	// Well-known set in RTT order; use the first that returns a usable result.
	for _, addr := range d.beacon.shuffledAddrs() {
		entries := beaconQueryServicesAt(ctx, d.beacon, addr, services)
		if entries != nil {
			return entries
		}
		// nil means unreachable; try next
	}
	return nil
}

// beaconQueryServicesAt queries addr for each service in sequence and returns
// the AID intersection. Returns nil if addr is unreachable on a query. Returns
// an empty (non-nil) slice when the peer is reachable but no AIDs match.
func beaconQueryServicesAt(ctx context.Context, b *beaconManager, addr net.Addr, services []string) []protocol.TopicEntry {
	now := time.Now()

	filterEntries := func(recs []protocol.SignedRecord, svc string) map[string]protocol.TopicEntry {
		m := make(map[string]protocol.TopicEntry)
		for _, r := range recs {
			if protocol.VerifySignedRecord(r, now) != nil {
				continue
			}
			e, err := protocol.TopicEntryFromSignedRecord(r)
			if err != nil || e.Topic != svc {
				continue
			}
			m[e.Address.String()] = e
		}
		return m
	}

	recs, _, err := b.node.FindValueWithNodes(ctx, addr, protocol.TopicNodeID(services[0]), protocol.RecTypeTopic, false)
	if err != nil {
		return nil // unreachable
	}
	candidates := filterEntries(recs, services[0])
	if len(candidates) == 0 || len(services) == 1 {
		out := make([]protocol.TopicEntry, 0, len(candidates))
		for _, e := range candidates {
			out = append(out, e)
		}
		if len(out) > 0 {
			b.queryHits.Add(1)
		}
		return out
	}

	for _, svc := range services[1:] {
		recs, _, err = b.node.FindValueWithNodes(ctx, addr, protocol.TopicNodeID(svc), protocol.RecTypeTopic, false)
		if err != nil {
			return nil // well-known address dropped mid-query; let caller try next
		}
		present := filterEntries(recs, svc)
		for aid := range candidates {
			if _, ok := present[aid]; !ok {
				delete(candidates, aid)
			}
		}
		if len(candidates) == 0 {
			return []protocol.TopicEntry{} // empty intersection for this address
		}
	}

	out := make([]protocol.TopicEntry, 0, len(candidates))
	for _, e := range candidates {
		out = append(out, e)
	}
	if len(out) > 0 {
		b.queryHits.Add(1)
	}
	return out
}
