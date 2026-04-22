// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
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
	// multi-service discover queries skip the beacon fallback. Below this the
	// DHT may not have enough density to cover all keys; above it the
	// intersection can be computed reliably from DHT results alone.
	beaconMultiServiceSizeThreshold = 500
)

// beaconManager handles supplemental store writes and last-resort read fallback
// via a set of infrastructure addresses resolved from DNS.
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
		b.log.Info("beacon: operator-configured beacon mode active")
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

// trySelfIdentify checks whether this node's public IP appears in addrs.
// If so, activates beacon mode and expands store capacity.
func (b *beaconManager) trySelfIdentify(addrs []net.Addr) {
	selfIP := b.node.SelfExtIP()
	if selfIP == nil {
		return
	}
	for _, a := range addrs {
		udp, ok := a.(*net.UDPAddr)
		if !ok {
			continue
		}
		if selfIP.Equal(udp.IP) {
			b.active.Store(true)
			b.node.SetMaxStoreKeys(beaconMaxStoreKeys)
			b.node.SetPassiveRouting(true)
			b.log.Info("beacon: self-identified via DNS, expanding store capacity")
			return
		}
	}
}

// RefreshAndStore re-resolves DNS (if stale) then fires StoreAll. Called each
// republish tick so beaconAddrs stay current without a dedicated timer.
func (b *beaconManager) RefreshAndStore(ctx context.Context, keys []a2al.NodeID) {
	addrs := b.refreshAddrs()
	if len(addrs) == 0 {
		return
	}
	b.StoreAll(ctx, keys)
}

// Addrs returns the current resolved beacon addresses.
func (b *beaconManager) Addrs() []net.Addr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.addrs
}

// shuffledAddrs returns beacon addresses sorted by ascending RTT (fastest
// first), excluding this node's own address. Addresses for which no RTT has
// been measured yet (never contacted) are appended after the known-RTT set.
// This gives a deterministic, performance-based preference without introducing
// random state, and naturally provides load spreading when the fastest beacon
// is consistently responsive.
func (b *beaconManager) shuffledAddrs() []net.Addr {
	selfIP := b.node.SelfExtIP()
	b.mu.RLock()
	raw := b.addrs
	b.mu.RUnlock()

	var known, unknown []net.Addr
	for _, a := range raw {
		if selfIP != nil {
			if udp, ok := a.(*net.UDPAddr); ok && selfIP.Equal(udp.IP) {
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

// StoreAll fires fire-and-forget STORE to every beacon address for each key,
// skipping any address that belongs to this node itself.
// When this node is itself a beacon it skips entirely: all publishers send
// StoreAt to every beacon directly, so beacon-to-beacon synchronisation is
// redundant and only adds unnecessary traffic.
func (b *beaconManager) StoreAll(ctx context.Context, keys []a2al.NodeID) {
	if b.active.Load() {
		// Self is a beacon node: other beacons already receive StoreAt from
		// every publisher. There is nothing useful to push.
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
					sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
					defer cancel()
					if _, err := b.node.StoreAt(sctx, a, k, r); err != nil {
						b.log.Debug("beacon store", "addr", a, "err", err)
					}
				}()
				b.storeSent.Add(1)
			}
		}
	}
}

// FindRecords tries beacon addresses in random order and returns results from
// the first address that responds without error. Because all beacon nodes
// receive the same STORE pushes they hold equivalent records; querying one is
// sufficient and the random order provides load balancing.
func (b *beaconManager) FindRecords(ctx context.Context, key a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	addrs := b.shuffledAddrs()
	if len(addrs) == 0 {
		return nil, nil
	}
	now := time.Now()
	for _, addr := range addrs {
		recs, _, err := b.node.FindValueWithNodes(ctx, addr, key, recType)
		if err != nil {
			b.log.Debug("beacon find", "addr", addr, "err", err)
			continue // beacon unreachable, try next
		}
		seen := map[string]struct{}{}
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
		}
		return out, nil // first successful contact; even empty is authoritative
	}
	return nil, nil
}

// Stats returns a map for merging into /debug/stats. Returns nil when this
// node is not operating in beacon mode, producing no output in the JSON
// response and keeping the beacon mechanism transparent to regular nodes.
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
		"beacon_store_sent": b.storeSent.Load(),
		"beacon_query_hits": b.queryHits.Load(),
	}
	if b.active.Load() {
		out["beacon_mode"] = true
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
			// NXDOMAIN: record actively removed — disable beacon.
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

// resolveFromBeacon attempts to resolve an endpoint record via beacon nodes.
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

// discoverFromBeacon queries a single randomly-chosen reachable beacon for all
// requested services and returns the AID intersection. Because every beacon
// receives STORE pushes from all nodes it holds equivalent records; using one
// beacon avoids redundant parallel queries while the random selection provides
// load balancing across multiple beacon addresses.
//
// When the estimated network size exceeds beaconMultiServiceSizeThreshold and
// len(services) > 1, the DHT is dense enough to serve the intersection reliably,
// so beacon is skipped to avoid inflating results from an auxiliary source.
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

	// Try beacons in random order; use the first one that responds.
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
// the AID intersection. Returns nil if the beacon is unreachable on any query.
// Returns an empty (non-nil) slice when the beacon is reachable but no results
// match.
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

	recs, _, err := b.node.FindValueWithNodes(ctx, addr, protocol.TopicNodeID(services[0]), protocol.RecTypeTopic)
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
		recs, _, err = b.node.FindValueWithNodes(ctx, addr, protocol.TopicNodeID(svc), protocol.RecTypeTopic)
		if err != nil {
			return nil // beacon went away mid-query; let caller try next
		}
		present := filterEntries(recs, svc)
		for aid := range candidates {
			if _, ok := present[aid]; !ok {
				delete(candidates, aid)
			}
		}
		if len(candidates) == 0 {
			return []protocol.TopicEntry{} // definitive empty from this beacon
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
