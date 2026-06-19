// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
	"github.com/a2al/a2al/transport"
)

// PunchTransport is the optional ICE hole-punch integration layer.
//
// When non-nil (injected via Config.PunchTransport), the DHT can reach
// NAT-bound peers that are not directly accessible over UDP. When nil
// (default), all DHT behaviour is identical to the current direct-UDP-only
// mode — no code paths change.
//
// The interface is intentionally narrow: DHT never sees QUIC connections,
// streams, or ICE candidates. It only asks "can I send this byte slice to
// that NodeID?" and "please start punching that NodeID in the background".
//
// Implementations live in the host layer (host/dht_punch_pool.go) and are
// wired in by the daemon at startup, following the same pattern as
// OnObservedAddr injection.
// PunchFailReason enumerates the reasons an ICE punch attempt can fail.
// Used by OnPunchComplete to enable differentiated handling in the DHT layer.
type PunchFailReason int

const (
	// PunchFailNone indicates success (used internally; callers check success bool).
	PunchFailNone PunchFailReason = 0

	// PunchFailNoAgent means the signaling hub reported the remote has no
	// registered callee (hub returned "noagent"). The remote is likely offline
	// or does not support ICE. The DHT can stop probing this peer.
	PunchFailNoAgent PunchFailReason = 1

	// PunchFailICETimeout means ICE negotiation started but connectivity checks
	// timed out. The remote may be temporarily offline or behind a symmetric NAT.
	PunchFailICETimeout PunchFailReason = 2

	// PunchFailOther covers all other errors (TLS, network I/O, dial errors).
	PunchFailOther PunchFailReason = 3
)

type PunchTransport interface {
	// SendTo attempts to deliver msg to nodeID via an existing punched QUIC
	// connection. ok=false means no active punched connection is available
	// for this peer; the caller must fall back to the UDP transport.
	// Called on the hot RPC path — must not block.
	SendTo(ctx context.Context, nodeID a2al.NodeID, msg []byte) (ok bool, err error)

	// Punch enqueues an asynchronous ICE hole-punch attempt for nodeID.
	// er supplies the signal URL and NAT classification from the peer's
	// signed endpoint record. priority is one of the PunchPriority*
	// constants. Non-blocking: returns immediately after enqueue.
	Punch(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int)

	// HasConn reports whether an active Mode B QUIC connection already exists
	// for nodeID. Used by triggerPunch to skip redundant punch attempts when
	// the pool already has a healthy connection.
	HasConn(nodeID a2al.NodeID) bool

	// InvalidateConn closes and evicts the Mode B QUIC connection for nodeID.
	// Called by sendAndWait when a QUIC-routed RPC times out, indicating the
	// connection is no longer viable. The next outboundPlan call will see
	// HasConn=false and fall back to UDP or deferICE naturally.
	// No-op when no connection exists for nodeID.
	InvalidateConn(nodeID a2al.NodeID)
}

// Punch priority levels for PunchTransport.Punch (§11 trigger table).
const (
	// PunchPriorityHigh is used by the replication maintainer (过程二) when
	// a ReplicationSet member goes Bad — this directly affects record availability.
	PunchPriorityHigh = 2
	// PunchPriorityLow is used by the health probe (过程三) when persistent
	// UDP failures indicate the peer is behind a restrictive NAT.
	PunchPriorityLow = 1
	// PunchPriorityLowest is used by the query engine when it encounters an
	// unreachable node while iterating — speculative, best-effort.
	PunchPriorityLowest = 0
)

// Config holds runtime dependencies for a DHT node (spec Step 7).
type Config struct {
	Transport transport.Transport
	Keystore  crypto.KeyStore
	// OnObservedAddr is called whenever a DHT response carries an observed_addr
	// (PONG, FIND_NODE_RESP, FIND_VALUE_RESP). reporter is the responding node's
	// NodeID; wire is the raw observed_addr bytes (6 or 18 bytes).
	// May be nil.
	OnObservedAddr func(reporter a2al.NodeID, wire []byte)
	// RecordAuth is an optional authority policy called by Store.Put after
	// signature/expiry verification passes (Phase 4: includes DHT key).
	// If nil, no authority check is performed (useful in tests).
	RecordAuth RecordAuthFunc
	// MaxStoreKeys limits the number of distinct DHT keys in the local store.
	// 0 uses DefaultMaxTotalKeys. Configurable per-node soft limit.
	MaxStoreKeys int
	// Logger is used for DHT-level diagnostics (send failures, RPC retries).
	// If nil, slog.Default() is used.
	Logger *slog.Logger
	// SeenPeersPath is the file path for persisting the seenPeers sliding-window
	// table across restarts (spec §7.3). Empty disables persistence (default in
	// tests). The file is written with mode 0600.
	SeenPeersPath string
	// PunchTransport is an optional ICE hole-punch integration.
	// When nil (default) the node operates in direct-UDP-only mode, which is
	// fully backward-compatible. Set by the host layer at startup via the same
	// injection pattern as OnObservedAddr.
	PunchTransport PunchTransport

	// LearnedPathFirst enables learned-path outbound selection (lastInbound,
	// skipCold, DeferICE). Default false preserves legacy direct-UDP behaviour.
	LearnedPathFirst bool

	// PushHandler is called when this node receives a MsgDHTPush (oneShot delivery).
	// Returns true if the record was new (daemon renews subscription via ACK).
	// Optional; nil disables push reception (node still participates as a pusher).
	PushHandler func(key a2al.NodeID, rec protocol.SignedRecord) bool
}

// PeerHealthState classifies a peer's reachability based on observed RPC outcomes.
type PeerHealthState uint8

const (
	PeerHealthUnknown PeerHealthState = iota // no RPC history yet
	PeerHealthGood                           // last RPC succeeded, failCount == 0
	PeerHealthBad                            // consecutive failures >= badHealthThreshold
)

// badHealthThreshold is the consecutive-failure count at which a peer is
// considered unreachable. Reset to 0 on the next successful RPC.
const badHealthThreshold = 2

// maxBackoffShift caps the bit-shift in the exponential backoff so
// nextRetryAt never overflows int64.  At shift=10 the penalty is
// probeInitDelay<<10 ≈ 8.5 h, which is effectively "give up for now".
const maxBackoffShift = 10

// correlatedFailThreshold is the number of distinct peers that must fail within
// correlatedFailWindow before the failures are considered correlated (i.e. caused
// by a local network outage rather than individual remote-side problems).
// When reached, SetOfflineSuspect(true) is called automatically.
const correlatedFailThreshold = 4

// correlatedFailWindow is the sliding time window over which distinct-peer
// failures are counted for correlated-failure detection.
const correlatedFailWindow = 15 * time.Second

// offlineSuspectThreshold is the quiet period without any successful outbound
// RPC after which the node suspects its own network connectivity is lost.
// Three probe ticks (3 × probeTickInterval = 45 s) provides enough margin
// to rule out a momentary lull while bounding damage from a real outage.
const offlineSuspectThreshold = 45 * time.Second

// familyHealth tracks reachability statistics for a single IP family (v4 or v6).
type familyHealth struct {
	failCount        int           // consecutive failures; reset to 0 on success
	pendingFailCount int           // failures held during suspected outage; settled or discarded by recordSuccess
	rtt              time.Duration // last successful RTT
	nextRetryAt      time.Time     // exponential backoff expiry; zero = contact freely
	lastSuccess      time.Time     // most recent success on this family; zero = never
	// everUsed is set when at least one RPC has been attempted on this family
	// (success or failure). Inactive families do not contribute to PeerHealthOf
	// aggregation, preserving equivalence with the old single-family model for
	// nodes that have only ever been contacted over one address family.
	everUsed bool

	// Inbound/outbound path hints (per address family).
	skipColdUDP   bool       // prefer ICE/QUIC over cold stable UDP; not a hard ban
	skipColdAt    time.Time  // when skipColdUDP was set
	lastInbound   *net.UDPAddr
	lastInboundAt time.Time
}

// familyFor returns a pointer to the family sub-struct corresponding to addr.
// Non-UDP addresses (e.g. MemTransport in tests) map to v4 by convention.
func (e *peerHealthEntry) familyFor(addr net.Addr) *familyHealth {
	if udp, ok := addr.(*net.UDPAddr); ok && udp.IP.To4() == nil {
		return &e.v6
	}
	return &e.v4
}

type peerHealthEntry struct {
	lastFailure   time.Time // most recent failure, any family; used by peerHealthForSort
	totalAttempts int       // lifetime RPC attempts, all families; never reset

	// isPunching indicates that an ICE hole-punch attempt is currently in
	// flight for this peer. While true the peer is excluded from all query
	// tracks (Good/Unknown/Bad) to avoid sending DHT messages to an address
	// that is not yet reachable. Cleared when the punch attempt completes
	// (success or failure). Populated by Phase 2 (punch scheduler); zero
	// value (false) preserves existing behaviour until then.
	isPunching bool

	v4 familyHealth // IPv4 address family health
	v6 familyHealth // IPv6 address family health
}

// Node is a single DHT participant (routing + local store + wire handler).
type Node struct {
	tr     transport.Transport
	ks     crypto.KeyStore
	addr   a2al.Address
	nid    a2al.NodeID
	table  *routing.Table
	store  *Store
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger

	pendMu sync.Mutex
	wait   map[string]*waitEntry

	peerMu sync.Mutex
	peers  map[string]*peerAddrs

	addrToID sync.Map // addr.String() → a2al.NodeID (reverse of peers map)

	recvOnce sync.Once
	wg       sync.WaitGroup

	tabMu sync.RWMutex // routing.Table (Add / NearestN)

	onObservedAddr func(reporter a2al.NodeID, wire []byte)
	auth           RecordAuthFunc // nil → no check

	selfExtMu   sync.RWMutex
	selfExtIP   net.IP // our own public IPv4 (set by host after STUN/HTTP probe)
	selfExtIPv6 net.IP // our own public IPv6 GUA (set by host after STUN/HTTP probe)

	statsRx  atomic.Uint64
	statsTx  atomic.Uint64
	statsRPC atomic.Uint64 // outbound request/response pairs (sendAndWait success)

	statsStoreRx        atomic.Uint64 // incoming STORE RPCs accepted by this node
	statsFindValueServed atomic.Uint64 // incoming FIND_VALUE RPCs answered with ≥1 record

	decodeErrNext atomic.Int64 // unix-nano: next time a decode-error WARN may fire

	// seenPeers maps NodeID → last tabAdd observation time (sliding-window stats).
	seenPeers     sync.Map
	seenPeersPath string // non-empty → persist to disk

	// seenThisBoot dedupes tabAdd-observed NodeIDs for unique_nodes_since_start.
	seenThisBoot        sync.Map // a2al.NodeID → struct{}
	seenUniqueSinceBoot atomic.Uint64

	healthMu sync.RWMutex
	health   map[string]*peerHealthEntry // key: nodeIDKey(id)

	// lastAnySuccessAt is the unix-nanosecond timestamp of the most recent
	// successful outbound RPC (updated by recordSuccess). Zero means no
	// success has been observed this session.
	// Used by suspectOffline to distinguish a local network outage from
	// genuine peer failures: if no success has been seen for
	// offlineSuspectThreshold, failure recording is suppressed so that
	// healthy peers are not penalised for our own connectivity loss.
	lastAnySuccessAt atomic.Int64

	// localOutageSuspect is set by the daemon when strong external evidence
	// of a local network outage is detected (sleep/wake, no default route).
	// It takes effect immediately, unlike the time-based offlineSuspectThreshold,
	// and is cleared automatically by recordSuccess on the first RPC success.
	localOutageSuspect atomic.Bool

	// correlatedFailMu guards correlatedFail* fields.
	correlatedFailMu sync.Mutex
	// correlatedFailPeers tracks distinct peers that failed within the current window.
	// A set (not a counter) prevents one misbehaving peer from inflating the count.
	// Cleared on any success.
	correlatedFailPeers map[string]struct{}
	// correlatedFailWindowStart is the start of the current counting window.
	// Resets when the threshold is reached or the window expires.
	correlatedFailWindowStart time.Time

	// NAT probe: SendNATProbeReq registers a token → notify channel here;
	// onNATProbeEcho delivers incoming echoes to the matching channel.
	natProbeMu   sync.Mutex
	natProbeWait map[string]chan struct{} // hex(8-byte token) → notification channel

	// Per-source-IP echo rate limit.
	natProbeEchoMu  sync.Mutex
	natProbeEchoMap map[string]*probeEchoEntry // srcIP string → rate entry

	repMu         sync.RWMutex
	repSets       map[repKey]*repSet    // (storeKey, publisher) → replication tracking
	replCh        chan replTask         // 过程一 → 过程二: replication work items
	renewInFlight map[repKey]struct{}   // keys with a renewBackground goroutine running

	// passiveRouting suppresses proactive FindNode queries when true.
	// Set via SetPassiveRouting; used by passive-mode nodes that fill their
	// routing table naturally through incoming traffic and do not need to
	// search for peers themselves.
	passiveRouting atomic.Bool

	// punch is the optional ICE hole-punch integration, injected via Config.
	// Nil when running in direct-UDP-only mode (default).
	punch PunchTransport

	// learnedPathFirst gates learned-path outbound selection (see sendplan.go).
	learnedPathFirst atomic.Bool

	// deliverPlanLogMu guards deliverPlanLogged (transition-only deliver plan debug).
	deliverPlanLogMu sync.Mutex
	deliverPlanLogged map[string]string // nodeIDKey(peer) → last logged plan signature

	// pushMu guards pushHandler.
	pushMu      sync.RWMutex
	// pushHandler is called when this node receives a MsgDHTPush from a DHT node.
	// Returns true if the message was new (causing the sender to renew its oneShot subscription).
	pushHandler func(key a2al.NodeID, rec protocol.SignedRecord) bool

	// recoveryNotify receives a token when recordSuccess detects the first
	// successful RPC after a suspectOffline period (long disconnect → reconnect).
	// Capacity 1; the sender is non-blocking so it never blocks the RPC hot path.
	recoveryNotify chan struct{}

	// epPrefetchNegMu guards epPrefetchNeg.
	epPrefetchNegMu sync.RWMutex
	// epPrefetchNeg suppresses redundant FindRecords calls for nodes whose
	// endpoint record was not found or whose lookup recently failed.
	//
	// Two tiers:
	//   ErrNoMatchingRecords (confirmed absent): retryAt = now+probeBadDelay,
	//     failCount set high so subsequent failures keep the 30-min interval.
	//   Network / timeout error (transient):     exponential backoff starting
	//     at probeInitDelay (30 s), doubling each failure, capped at
	//     probeBadDelay (30 min).
	//
	// The entry is deleted whenever an endpoint record for the same nodeID is
	// written to the local store by any code path (see clearEpPrefetchNeg).
	epPrefetchNeg map[string]epPrefetchNegEntry // nodeIDKey(id) → entry

}

type waitEntry struct {
	want uint8
	ch   chan *protocol.DecodedMessage
}

// probeEchoEntry tracks the per-source-IP echo rate for NAT probe requests.
type probeEchoEntry struct {
	windowEnd time.Time
	count     int
}

// NewNode builds a node; keystore must list exactly one address (Phase 1).
func NewNode(cfg Config) (*Node, error) {
	if cfg.Transport == nil || cfg.Keystore == nil {
		return nil, errors.New("dht: transport and keystore required")
	}
	addrs, err := cfg.Keystore.List()
	if err != nil {
		return nil, err
	}
	if len(addrs) != 1 {
		return nil, errors.New("dht: keystore must hold exactly one identity")
	}
	addr := addrs[0]
	nid := a2al.NodeIDFromAddress(addr)
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		tr:             cfg.Transport,
		ks:             cfg.Keystore,
		addr:           addr,
		nid:            nid,
		store:          NewStore(cfg.RecordAuth, cfg.MaxStoreKeys),
		ctx:            ctx,
		cancel:         cancel,
		log:            logger,
		wait:            make(map[string]*waitEntry),
		peers:           make(map[string]*peerAddrs),
		health:          make(map[string]*peerHealthEntry),
		natProbeWait:    make(map[string]chan struct{}),
		natProbeEchoMap: make(map[string]*probeEchoEntry),
		repSets:        make(map[repKey]*repSet),
		replCh:         make(chan replTask, replChBuf),
		renewInFlight:     make(map[repKey]struct{}),
		epPrefetchNeg:  make(map[string]epPrefetchNegEntry),
		deliverPlanLogged: make(map[string]string),
		onObservedAddr:    cfg.OnObservedAddr,
		auth:           cfg.RecordAuth,
		punch:          cfg.PunchTransport,
		pushHandler:    cfg.PushHandler,
		recoveryNotify: make(chan struct{}, 1),
	}
	n.learnedPathFirst.Store(cfg.LearnedPathFirst)
	n.table = routing.NewTable(nid, nil)
	if cfg.SeenPeersPath != "" {
		n.seenPeersPath = cfg.SeenPeersPath
		n.loadSeenPeers(cfg.SeenPeersPath)
	}
	return n, nil
}

// Start begins the inbound packet loop and background maintenance workers.
func (n *Node) Start() {
	n.recvOnce.Do(func() {
		n.wg.Add(1)
		go n.recvLoop()
		if n.seenPeersPath != "" {
			n.startSeenPeersFlusher()
		}
		n.startReplicationWorkers()
	})
}

func (n *Node) recvLoop() {
	defer n.wg.Done()
	for {
		data, from, err := n.tr.Receive()
		if err != nil {
			return
		}
		dec, err := protocol.VerifyAndDecode(data)
		if err != nil {
			now := time.Now().UnixNano()
			if n.decodeErrNext.Load() <= now {
				n.decodeErrNext.Store(now + int64(30*time.Second))
				n.log.Warn("dht decode failed", "from", from, "err", err)
			}
			continue
		}
		n.statsRx.Add(1)
		if n.tryDeliver(dec) {
			continue
		}
		switch dec.Header.MsgType {
		case protocol.MsgPong, protocol.MsgFindValueResp, protocol.MsgFindNodeResp, protocol.MsgStoreResp,
			protocol.MsgDHTPushACK:
			continue
		}
		n.dispatchIncoming(from, inboundChannelUDP, dec)
	}
}

func (n *Node) dispatchIncoming(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.inboundLearn(from, ch, dec)
	switch dec.Header.MsgType {
	case protocol.MsgPing:
		n.onPing(from, ch, dec)
	case protocol.MsgFindNode:
		n.onFindNode(from, ch, dec)
	case protocol.MsgFindValue:
		n.onFindValue(from, ch, dec)
	case protocol.MsgStore:
		n.onStore(from, ch, dec)
	case protocol.MsgNATProbeReq:
		n.onNATProbeReq(from, ch, dec)
	case protocol.MsgNATProbeEcho:
		n.onNATProbeEcho(from, ch, dec)
	case protocol.MsgDHTPush:
		n.onDHTPush(from, ch, dec)
	default:
	}
}

// InjectReceived processes a pre-received DHT message from an external
// transport (e.g. a punched QUIC stream managed by the host layer).
//
// It follows the same decode→dispatch path as recvLoop without reading from
// the UDP transport. from should be the peer's reachable net.Addr so that
// outbound responses can be addressed correctly; the host layer supplies the
// ICE-negotiated address or the peer's reflexive candidate.
//
// Safe to call from any goroutine concurrently with the normal UDP receive loop.
func (n *Node) InjectReceived(data []byte, from net.Addr) {
	dec, err := protocol.VerifyAndDecode(data)
	if err != nil {
		return
	}
	n.statsRx.Add(1)
	if n.tryDeliver(dec) {
		return
	}
	switch dec.Header.MsgType {
	case protocol.MsgPong, protocol.MsgFindValueResp, protocol.MsgFindNodeResp, protocol.MsgStoreResp,
		protocol.MsgDHTPushACK:
		return
	}
	n.dispatchIncoming(from, inboundChannelQUIC, dec)
}

func (n *Node) tryDeliver(dec *protocol.DecodedMessage) bool {
	key := string(dec.Header.TxID)
	n.pendMu.Lock()
	w, ok := n.wait[key]
	if !ok || w.want != dec.Header.MsgType {
		n.pendMu.Unlock()
		return false
	}
	delete(n.wait, key)
	n.pendMu.Unlock()
	select {
	case w.ch <- dec:
	default:
	}
	return true
}

func (n *Node) registerWait(txID []byte, want uint8) chan *protocol.DecodedMessage {
	ch := make(chan *protocol.DecodedMessage, 1)
	n.pendMu.Lock()
	n.wait[string(txID)] = &waitEntry{want: want, ch: ch}
	n.pendMu.Unlock()
	return ch
}

func (n *Node) unregisterWait(txID []byte) {
	n.pendMu.Lock()
	delete(n.wait, string(txID))
	n.pendMu.Unlock()
}

func (n *Node) lookupPeer(id a2al.NodeID) (net.Addr, bool) {
	n.peerMu.Lock()
	defer n.peerMu.Unlock()
	pa := n.peers[nodeIDKey(id)]
	if pa == nil {
		return nil, false
	}
	a := pa.preferred()
	return a, a != nil
}

// lookupPeerHealthAware returns the best dial address for id that is not
// currently in back-off, selecting between v4 and v6 based on health state.
//
// Unlike lookupPeer (which blindly prefers v4 anchor/live), this function skips a
// family whose back-off window has not expired and tries the other family
// instead.  Specifically:
//   - If v4 anchor or live is known and its back-off has expired (or it was never
//     used), return that address.
//   - Else if v6 anchor or live is known and its back-off has expired (or it was
//     never used), return that address.
//   - If all known addresses are in back-off, return nil, false.
//
// An "unused" family (everUsed=false) counts as back-off expired — it means
// we have no history for that path and should try it freely.
//
// ephemeral (hole-punch) addresses are not considered here; they are handled
// by the ICE punch path, not the replication store path.
func (n *Node) lookupPeerHealthAware(id a2al.NodeID) (net.Addr, bool) {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa == nil {
		return nil, false
	}

	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()

	now := time.Now()
	v4ok := e == nil || !e.v4.everUsed || e.v4.nextRetryAt.IsZero() || now.After(e.v4.nextRetryAt)
	v6ok := e == nil || !e.v6.everUsed || e.v6.nextRetryAt.IsZero() || now.After(e.v6.nextRetryAt)

	if pa.v4.bestStable() != nil && v4ok {
		return pa.v4.bestStable(), true
	}
	if pa.v6.bestStable() != nil && v6ok {
		return pa.v6.bestStable(), true
	}
	return nil, false
}

// lookupFamilyHealthAware returns the stable dial address for a single IP
// family when that family is not in back-off. Unlike lookupPeerHealthAware it
// never falls back to the other family: a nil/false result means the requested
// family has no known address or is currently penalised.
func (n *Node) lookupFamilyHealthAware(id a2al.NodeID, v6 bool) (net.Addr, bool) {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa == nil {
		return nil, false
	}
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	now := time.Now()
	if v6 {
		ok := e == nil || !e.v6.everUsed || e.v6.nextRetryAt.IsZero() || now.After(e.v6.nextRetryAt)
		if pa.v6.bestStable() != nil && ok {
			return pa.v6.bestStable(), true
		}
	} else {
		ok := e == nil || !e.v4.everUsed || e.v4.nextRetryAt.IsZero() || now.After(e.v4.nextRetryAt)
		if pa.v4.bestStable() != nil && ok {
			return pa.v4.bestStable(), true
		}
	}
	return nil, false
}

// rememberLiveRank infers Live-slot rank from a stored endpoint declaration.
// This trusts the peer's self-reported NatType; it is not proof of RPC success.
// Stronger Verified evidence comes from outbound recordSuccess paths (Phase 2).
func (n *Node) rememberLiveRank(id a2al.NodeID) addrRank {
	recs := n.LocalStoreGet(id, protocol.RecTypeEndpoint)
	for _, sr := range recs {
		if er, err := protocol.ParseEndpointRecord(sr); err == nil {
			if er.NatType < protocol.NATSymmetric {
				return rankVerified
			}
			break
		}
	}
	return rankHearsay
}

func (n *Node) remember(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	id := a2al.NodeIDFromAddress(dec.SenderAddr)
	liveRank := n.rememberLiveRank(id)
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	if pa == nil {
		pa = &peerAddrs{}
		n.peers[nodeIDKey(id)] = pa
	}
	// Mode B QUIC inject uses ICE RemoteAddr; do not treat it as a portable
	// stable anchor (M6). HasConn is authoritative for outbound on that path.
	if ch != inboundChannelQUIC {
		if udp, ok := from.(*net.UDPAddr); ok {
			pa.tryLive(udp, liveRank)
		} else {
			pa.fallback = from
		}
	}
	n.peerMu.Unlock()
	n.addrToID.Store(from.String(), id)
	// Inbound message = direct-contact evidence; set VerifiedAt now.
	n.tabAdd(nodeInfoFromMessage(dec, from), routing.EntryMeta{VerifiedAt: time.Now()}, from)
}

// tabAdd inserts or refreshes ni in the routing table.
//
// directFrom is the transport address the inbound message arrived on. When it is
// a *net.UDPAddr, endpoint records may also populate the peer Anchor dial slot;
// non-UDP paths (e.g. MemTransport in tests) only upgrade the routing table.
func (n *Node) tabAdd(ni protocol.NodeInfo, meta routing.EntryMeta, directFrom net.Addr) {
	var nid a2al.NodeID
	if len(ni.NodeID) != len(nid) {
		return
	}
	copy(nid[:], ni.NodeID)

	// P0: only record verified (direct) contact in seenPeers statistics.
	if !meta.VerifiedAt.IsZero() {
		n.recordPeerSeen(nid)
	}

	now := time.Now()

	if meta.VerifiedAt.IsZero() {
		// Hearsay path: delegate entirely to the routing layer (main or pending).
		n.tabMu.Lock()
		n.table.Add(ni, meta, now)
		n.tabMu.Unlock()
		return
	}

	// Direct-contact path: existing manual LRU-eviction logic.
	//
	// If the peer self-advertises a stable quic:// address and the caller
	// supplied an ephemeral address (e.g. from ICE), prefer the advertised one
	// so the routing table always points to the persistent port.
	//
	// NATType gate: NATUnknown, NATFullCone, NATRestricted, and NATPortRestricted
	// all publish a stable v4 port (EIM mapping), so their advertised address is a
	// reliable routing anchor. NATSymmetric allocates a different external port per
	// destination and must NOT override an ephemeral address that was actually used —
	// the published port is unlikely to match the port the NAT will use next time.
	//
	// Use family-aware lookup to avoid replacing ni.IP with a different-family address.
	if len(ni.IP) > 0 {
		recs := n.LocalStoreGet(nid, protocol.RecTypeEndpoint)
		for _, sr := range recs {
			if er, err := protocol.ParseEndpointRecord(sr); err == nil {
				if er.NatType < protocol.NATSymmetric {
					ref := &net.UDPAddr{IP: net.IP(ni.IP)}
					if ua := firstEndpointAddrForFamily(&er, ref); ua != nil {
						if ip4 := ua.IP.To4(); ip4 != nil {
							ni.IP = append([]byte(nil), ip4...)
						} else {
							ni.IP = append([]byte(nil), ua.IP.To16()...)
						}
						ni.Port = uint16(ua.Port)
						if _, ok := directFrom.(*net.UDPAddr); ok {
							n.BindPeerAnchor(nid, ua)
						}
					}
				}
				break
			}
		}
	}

	n.tabMu.Lock()
	if n.table.Contains(nid) {
		n.table.Add(ni, meta, now) // touch + update IP:Port + update VerifiedAt
		n.tabMu.Unlock()
		return
	}
	if n.table.PeerBucketLen(nid) < routing.K {
		n.table.Add(ni, meta, now)
		n.tabMu.Unlock()
		return
	}
	// Phase 3: before pinging the LRU direct node, check whether a punched
	// entry exists in this bucket. Punched entries are second-class citizens
	// and are evicted first — no liveness probe required.
	punchedOldest, hasPunched := n.table.OldestPunchedInBucket(nid)
	if hasPunched {
		var punchedID a2al.NodeID
		copy(punchedID[:], punchedOldest.NodeID)
		n.table.Remove(punchedID)
		n.table.Add(ni, meta, now)
		n.tabMu.Unlock()
		return
	}
	oldest, ok := n.table.OldestInBucket(nid)
	n.tabMu.Unlock()
	if !ok {
		return
	}
	var oldID a2al.NodeID
	copy(oldID[:], oldest.NodeID)
	pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr, found := n.lookupPeer(oldID)
	if found && n.Ping(pctx, addr) == nil {
		return
	}
	n.tabMu.Lock()
	n.table.Remove(oldID)
	n.table.Add(ni, meta, now)
	n.tabMu.Unlock()
}

// tabAddPunched admits a peer that was reached via ICE hole-punching into the
// routing table's punched zone (spare slots only, never evicts direct nodes).
// Called by OnPunchComplete after the host layer confirms ICE success.
func (n *Node) tabAddPunched(ni protocol.NodeInfo, meta routing.EntryMeta) {
	if len(ni.NodeID) != len(a2al.NodeID{}) {
		return
	}
	var nid a2al.NodeID
	copy(nid[:], ni.NodeID)
	if nid == n.nid {
		return
	}
	now := time.Now()
	n.tabMu.Lock()
	n.table.AddPunched(ni, meta, now)
	n.tabMu.Unlock()
}

func (n *Node) tabNearest(target a2al.NodeID, k int) []protocol.NodeInfo {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.NearestN(target, k)
}

// verifiedFreshWindow is the age threshold for Verified-Fresh classification.
// Aligns with endpointRecordTTL/2 (3600s / 2 = 1800s = 30 min).
const verifiedFreshWindow = 30 * time.Minute

// tabNearestVerified returns up to k verified nodes closest to target, ordered
// Verified-Fresh first.  Used for FIND_NODE and FIND_VALUE responses to ensure
// only directly-verified nodes are propagated (one-hop communication principle).
//
// Starvation protection: if the verified pool is smaller than k/2, the result
// is padded with entries from tabNearestHealthy (which includes unverified nodes)
// to avoid returning an empty response during cold-start or sparse-network periods.
func (n *Node) tabNearestVerified(target a2al.NodeID, k int) []protocol.NodeInfo {
	cutoff := time.Now().Add(-verifiedFreshWindow)
	n.tabMu.RLock()
	all := n.table.NearestNVerified(target, routing.K*4, cutoff)
	n.tabMu.RUnlock()

	// Apply dht-layer PeerHealth filter: exclude Bad nodes.
	var result []protocol.NodeInfo
	for _, ni := range all {
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if n.PeerHealthOf(id) == PeerHealthBad {
			continue
		}
		result = append(result, ni)
	}
	if len(result) > k {
		result = result[:k]
	}

	// Starvation fallback: pad with healthy nodes if verified pool is small.
	if len(result) < k/2 {
		extra := n.tabNearestHealthy(target, k)
		seen := make(map[string]struct{}, len(result))
		for _, ni := range result {
			seen[string(ni.NodeID)] = struct{}{}
		}
		for _, ni := range extra {
			if _, ok := seen[string(ni.NodeID)]; !ok {
				result = append(result, ni)
				if len(result) >= k {
					break
				}
			}
		}
	}
	return result
}

// PeerRTT returns the last measured round-trip time for addr, or 0 if the
// address is not yet known or has never completed a successful exchange.
func (n *Node) PeerRTT(addr net.Addr) time.Duration {
	id, ok := n.lookupPeerID(addr)
	if !ok {
		return 0
	}
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	if e == nil {
		return 0
	}
	return e.familyFor(addr).rtt
}

// lookupPeerID returns the NodeID associated with addr, if known.
func (n *Node) lookupPeerID(addr net.Addr) (a2al.NodeID, bool) {
	v, ok := n.addrToID.Load(addr.String())
	if !ok {
		return a2al.NodeID{}, false
	}
	return v.(a2al.NodeID), true
}

// adaptNodeListForAsker rewrites each NodeInfo's IP:Port for FIND_* responses.
// Priority per node (aligned with tabAdd endpoint upgrade): endpoint anchor
// (NatType < Symmetric) → routing-table IP:Port → peers bestStable fallback.
func (n *Node) adaptNodeListForAsker(nodes []protocol.NodeInfo, asker net.Addr) []protocol.NodeInfo {
	askerUDP, ok := asker.(*net.UDPAddr)
	if !ok {
		return nodes // non-UDP asker: adaptation not possible
	}
	askerIsV4 := askerUDP.IP.To4() != nil
	out := make([]protocol.NodeInfo, 0, len(nodes))
	for _, ni := range nodes {
		var id a2al.NodeID
		if len(ni.NodeID) == len(id) {
			copy(id[:], ni.NodeID)
			ni = n.adaptNodeInfoForAsker(ni, id, askerIsV4)
		}
		out = append(out, ni)
	}
	return out
}

// adaptNodeInfoForAsker rewrites ni.IP/Port for propagation to asker.
func (n *Node) adaptNodeInfoForAsker(ni protocol.NodeInfo, id a2al.NodeID, askerIsV4 bool) protocol.NodeInfo {
	familyRef := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if !askerIsV4 {
		familyRef = &net.UDPAddr{IP: net.IPv6loopback}
	}
	for _, sr := range n.LocalStoreGet(id, protocol.RecTypeEndpoint) {
		if er, err := protocol.ParseEndpointRecord(sr); err == nil {
			if er.NatType < protocol.NATSymmetric {
				if ua := firstEndpointAddrForFamily(&er, familyRef); ua != nil {
					return nodeInfoWithUDPAddr(ni, ua)
				}
			}
			break
		}
	}
	if len(ni.IP) > 0 && ni.Port != 0 {
		return ni
	}
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa == nil {
		return ni
	}
	var addr *net.UDPAddr
	if askerIsV4 {
		addr = pa.v4.bestStable()
		if addr == nil {
			addr = pa.v6.bestStable()
		}
	} else {
		addr = pa.v6.bestStable()
		if addr == nil {
			addr = pa.v4.bestStable()
		}
	}
	if addr == nil {
		return ni
	}
	return nodeInfoWithUDPAddr(ni, addr)
}

func nodeInfoWithUDPAddr(ni protocol.NodeInfo, addr *net.UDPAddr) protocol.NodeInfo {
	result := ni
	if ip4 := addr.IP.To4(); ip4 != nil {
		result.IP = append([]byte(nil), ip4...)
	} else {
		result.IP = append([]byte(nil), addr.IP.To16()...)
	}
	result.Port = uint16(addr.Port)
	return result
}

// recordSuccess marks the peer's address family as healthy: resets that
// family's failCount, clears its backoff, and updates RTT.
// Also refreshes the routing table VerifiedAt timestamp.
//
// recordSuccess marks the peer's address family as healthy: resets that
// family's failCount, clears its backoff, and updates RTT.
// Also refreshes the routing table VerifiedAt timestamp.
// On confirmed outage (suspectOffline), clears all pending failures globally.
func (n *Node) recordSuccess(id a2al.NodeID, addr net.Addr, rtt time.Duration) {
	key := nodeIDKey(id)
	now := time.Now()
	// Read suspectOffline before updating lastAnySuccessAt/localOutageSuspect
	// so it reflects the state that produced any pending failures.
	wasSuspect := n.suspectOffline()
	if wasSuspect {
		select {
		case n.recoveryNotify <- struct{}{}:
		default:
		}
	}
	n.lastAnySuccessAt.Store(now.UnixNano())
	n.localOutageSuspect.Store(false) // clear explicit outage flag set by daemon
	n.correlatedFailMu.Lock()
	n.correlatedFailPeers = nil // reset breadth window on any success
	n.correlatedFailMu.Unlock()
	n.healthMu.Lock()

	// Confirmed outage: discard all pending and reset backoff globally.
	if wasSuspect {
		for _, pe := range n.health {
			pe.v4.pendingFailCount = 0
			pe.v6.pendingFailCount = 0
			pe.v4.nextRetryAt = time.Time{}
			pe.v6.nextRetryAt = time.Time{}
		}
	}
	// Non-suspect path: each peer settles its own pending on its own success.

	e := n.health[key]
	if e == nil {
		e = &peerHealthEntry{}
		n.health[key] = e
	}
	e.totalAttempts++
	fh := e.familyFor(addr)
	fh.everUsed = true
	fh.failCount = 0
	fh.pendingFailCount = 0
	fh.nextRetryAt = time.Time{}
	fh.lastSuccess = now
	n.clearSkipColdUDP(fh)
	if rtt > 0 {
		fh.rtt = rtt
	}
	n.healthMu.Unlock()

	if udp, ok := addr.(*net.UDPAddr); ok {
		n.bindPeerLive(id, udp, rankVerified)
	}

	// Update the routing layer's freshness timestamp.  This covers the outbound
	// RPC path; the inbound path (remember) is covered by tabAdd with VerifiedAt=now.
	n.tabMu.Lock()
	n.table.UpdateVerifiedAt(id, now)
	n.tabMu.Unlock()

}

// recordFailure increments the consecutive-failure counter for the address
// family used by addr, and sets an exponential back-off on that family.
//
// When suspectOffline is true (no successful RPC for offlineSuspectThreshold),
// failCount and nextRetryAt are suppressed: healthy peers must not be penalised
// for a local network outage.  lastFailure and totalAttempts are still updated
// so diagnostic counters remain accurate.
func (n *Node) recordFailure(id a2al.NodeID, addr net.Addr) {
	// Endpoint lookup touches the store; never call it while holding healthMu.
	hasSignal := n.lookupEndpointRecord(id) != nil

	key := nodeIDKey(id)
	n.healthMu.Lock()
	e := n.health[key]
	if e == nil {
		e = &peerHealthEntry{}
		n.health[key] = e
	}
	e.lastFailure = time.Now()
	e.totalAttempts++
	if n.suspectOffline() {
		n.healthMu.Unlock()
		return
	}
	fh := e.familyFor(addr)
	fh.everUsed = true
	// Accumulate into pendingFailCount instead of failCount directly.
	// pendingFailCount contributes to PeerHealthOf immediately (see
	// familyHealthState), so query routing still deprioritises this peer.
	// Settlement happens per-peer in recordSuccess:
	//   - wasSuspect=true  → all pending globally discarded; failCount stays
	//                         at 0, peer instantly recovers from Bad.
	//   - wasSuspect=false → only THIS peer's pending is cleared (self-
	//                         settlement). Other peers retain their pending
	//                         until they each individually succeed, so genuine
	//                         bad peers cannot hide behind an unrelated success.
	fh.pendingFailCount++
	// nextRetryAt uses the combined (failCount + pendingFailCount) projection
	// to prevent tight-loop retries regardless of settlement outcome.
	combined := fh.failCount + fh.pendingFailCount
	shift := combined - 1
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	fh.nextRetryAt = time.Now().Add(probeInitDelay << shift)
	turnedBad := combined >= badHealthThreshold
	// Set skip-cold when the peer has a Signal URL and UDP has proven persistently
	// unreliable (combined failures reach Bad threshold).  Previously this only
	// fired for ReachNAT peers; extending to any peer with a signal URL lets
	// ReachPublic nodes (anchor present but anchor unreachable) also upgrade to
	// ICE on the next renewal cycle.  Gating on turnedBad avoids triggering ICE
	// for single transient timeouts.
	if hasSignal && turnedBad {
		fh.skipColdUDP = true
		fh.skipColdAt = time.Now()
	}
	n.healthMu.Unlock()

	if turnedBad {
		// Revoke the fresh-live preference the same way the original code did:
		// once the combined failure count crosses the threshold, stop preferring
		// the observed path over the advertised anchor.
		n.peerMu.Lock()
		if pa := n.peers[key]; pa != nil {
			if udp, ok := addr.(*net.UDPAddr); ok && udp != nil {
				pa.familyFor(udp).liveAt = time.Time{}
			} else {
				pa.v4.liveAt = time.Time{}
			}
		}
		n.peerMu.Unlock()
	}

	// Correlated-failure detection: track distinct peers failing within a
	// short window. Using a set ensures a single misbehaving peer that fails
	// repeatedly cannot trigger the outage signal on its own. If enough
	// distinct peers fail without any recent success, the failures are almost
	// certainly caused by a local network outage rather than individual
	// remote-side problems. Trigger SetOfflineSuspect immediately so
	// subsequent recordFailure calls are suppressed.
	//
	// Two guards prevent false positives:
	//
	//  1. Cold start (lastAnySuccessAt==0): never triggered. Before any
	//     successful RPC we cannot distinguish dead seeds from a local
	//     outage — same reasoning as the last==0 guard in suspectOffline().
	//
	//  2. Recent success within correlatedFailWindow: not triggered even
	//     when the distinct-peer count reaches the threshold. During
	//     bootstrap a node may quickly succeed with one seed while many
	//     others are dead; the interleaved successes prove connectivity is
	//     up, so failures are seed-quality heterogeneity, not an outage.
	//     Only when the last success is older than the window (i.e. no
	//     success for ≥15 s AND 4 distinct peers failed) do we conclude
	//     that the outage likely started.
	lastSuccessNano := n.lastAnySuccessAt.Load()
	if lastSuccessNano == 0 {
		return
	}
	now := time.Now()
	n.correlatedFailMu.Lock()
	if n.correlatedFailWindowStart.IsZero() || now.Sub(n.correlatedFailWindowStart) > correlatedFailWindow {
		// Start a fresh window with this peer as the first entry.
		n.correlatedFailPeers = map[string]struct{}{key: {}}
		n.correlatedFailWindowStart = now
	} else {
		if n.correlatedFailPeers == nil {
			n.correlatedFailPeers = make(map[string]struct{})
		}
		n.correlatedFailPeers[key] = struct{}{}
	}
	// Only trigger when the threshold is reached AND the last success
	// predates the current window — proving the failures are not merely
	// interleaved with ongoing connectivity.
	reachedThreshold := len(n.correlatedFailPeers) >= correlatedFailThreshold
	lastSuccessBeforeWindow := now.Sub(time.Unix(0, lastSuccessNano)) >= correlatedFailWindow
	triggered := reachedThreshold && lastSuccessBeforeWindow
	n.correlatedFailMu.Unlock()

	if triggered {
		n.SetOfflineSuspect(true)
	}
}

// PeerAllowContact returns true if at least one address family's back-off for
// this peer has expired (or was never set). Contact is permitted when any
// family is available — callers use whichever family succeeds.
func (n *Node) PeerAllowContact(id a2al.NodeID) bool {
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	if e == nil {
		return true
	}
	now := time.Now()
	v4ok := e.v4.nextRetryAt.IsZero() || now.After(e.v4.nextRetryAt)
	v6ok := e.v6.nextRetryAt.IsZero() || now.After(e.v6.nextRetryAt)
	return v4ok || v6ok
}

// suspectOffline reports whether the node suspects its own network connectivity
// is lost. Returns true when at least one successful RPC has been observed
// this session but no success has occurred for longer than offlineSuspectThreshold.
//
// When true, recordFailure suppresses failCount and nextRetryAt accumulation
// so healthy peers are not penalised for a local outage. Any recordSuccess
// call clears the condition immediately.
func (n *Node) suspectOffline() bool {
	if n.localOutageSuspect.Load() {
		return true
	}
	last := n.lastAnySuccessAt.Load()
	if last == 0 {
		return false // never succeeded this session; new node, do not assume offline
	}
	return time.Since(time.Unix(0, last)) > offlineSuspectThreshold
}

// SetOfflineSuspect lets the daemon signal that local network connectivity
// is known to be unavailable (e.g. sleep/wake detected, no default route).
// recordSuccess clears the flag automatically when the first RPC succeeds.
// When v is true, any accumulated pending failures are discarded immediately
// so they cannot be flushed into failCount on the next success.
func (n *Node) SetOfflineSuspect(v bool) {
	n.localOutageSuspect.Store(v)
	if v {
		n.healthMu.Lock()
		for _, pe := range n.health {
			pe.v4.pendingFailCount = 0
			pe.v6.pendingFailCount = 0
			// Clear nextRetryAt so PeerAllowContact stays consistent with
			// PeerHealthOf: once pending is discarded the peer is no longer
			// Bad, and callers should be allowed to retry immediately.
			pe.v4.nextRetryAt = time.Time{}
			pe.v6.nextRetryAt = time.Time{}
		}
		n.healthMu.Unlock()
	}
}

// RecoveryNotify returns the channel that receives a token whenever the node
// recovers from a suspected-offline period (first successful RPC after
// ≥ offlineSuspectThreshold without any success). The channel has capacity 1;
// the caller should consume tokens promptly to avoid missing events.
func (n *Node) RecoveryNotify() <-chan struct{} {
	return n.recoveryNotify
}

// RelaxHealthThrottle caps the nextRetryAt of all known peers to at most
// now+cap. Peers whose backoff expires sooner, or who have no backoff, are
// unaffected. failCount is intentionally preserved so the exponential-backoff
// schedule is not fully discarded, only shortened.
//
// Call this after a confirmed network recovery to let probe and replication
// loops reach throttled peers within cap, rather than waiting out potentially
// long backlogs accumulated during the outage.
func (n *Node) RelaxHealthThrottle(dur time.Duration) {
	deadline := time.Now().Add(dur)
	n.healthMu.Lock()
	for _, e := range n.health {
		if !e.v4.nextRetryAt.IsZero() && e.v4.nextRetryAt.After(deadline) {
			e.v4.nextRetryAt = deadline
		}
		if !e.v6.nextRetryAt.IsZero() && e.v6.nextRetryAt.After(deadline) {
			e.v6.nextRetryAt = deadline
		}
	}
	n.healthMu.Unlock()
}

// peerHealthForSort returns the lastFailure time and totalAttempts for a peer,
// used by the query engine to sort bad-node candidates.  Returns zero values
// if no health entry exists yet.
func (n *Node) peerHealthForSort(id a2al.NodeID) (lastFailure time.Time, totalAttempts int) {
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	if e == nil {
		return
	}
	return e.lastFailure, e.totalAttempts
}

// recordProbeFailure is called by healthProbeLoop after a dedicated PING
// fails on addr.  A health probe is not a "real" contact attempt — its sole
// purpose is to check liveness — so its failure should not carry the same
// weight as a failed StoreAt or FindNode.
//
// We undo the familyHealth.failCount increment that PingIdentity's internal
// recordFailure applied (net effect on failCount: zero) and halve the
// remaining back-off instead of growing it, for the family matching addr.
func (n *Node) recordProbeFailure(id a2al.NodeID, addr net.Addr) {
	n.healthMu.Lock()
	defer n.healthMu.Unlock()
	e := n.health[nodeIDKey(id)]
	if e == nil {
		return
	}
	fh := e.familyFor(addr)
	// Undo the pendingFailCount++ that PingIdentity's sendAndWait applied.
	// (recordFailure now writes to pendingFailCount, not failCount directly.)
	if fh.pendingFailCount > 0 {
		fh.pendingFailCount--
	} else if fh.failCount > 0 {
		// Fallback: handle the case where pending was already flushed.
		fh.failCount--
	}
	// Halve the remaining back-off window instead of growing it.
	if !fh.nextRetryAt.IsZero() {
		remaining := time.Until(fh.nextRetryAt)
		if remaining <= 0 {
			fh.nextRetryAt = time.Time{}
		} else {
			fh.nextRetryAt = time.Now().Add(remaining / 2)
		}
	}
}

// familyHealthState classifies the health state of a single family sub-entry.
// Returns PeerHealthUnknown when the family has never been used (everUsed=false),
// which prevents inactive families from biasing the aggregate result.
//
// Both failCount and pendingFailCount contribute to the Bad threshold.
// pendingFailCount holds failures not yet settled: discarded globally on
// confirmed outage (wasSuspect or SetOfflineSuspect), or cleared per-peer
// when that peer individually succeeds (self-settlement). Including both
// here ensures query routing deprioritises unreliable peers immediately —
// while still allowing instant recovery once the outage is confirmed.
func familyHealthState(fh *familyHealth) PeerHealthState {
	if !fh.everUsed {
		return PeerHealthUnknown // sentinel: inactive family
	}
	if fh.failCount+fh.pendingFailCount >= badHealthThreshold {
		return PeerHealthBad
	}
	if !fh.lastSuccess.IsZero() {
		return PeerHealthGood
	}
	return PeerHealthUnknown
}

// PeerHealthOf returns the aggregate health state across both address families.
//
// Aggregation rules (designed to preserve exact backward-compatibility for
// single-family v4-only nodes during the migration period):
//   - Any active family Good  → PeerHealthGood
//   - All active families Bad → PeerHealthBad
//   - No active family at all → PeerHealthUnknown
//
// Exception: if any family has a fresh lastInbound (within lastInboundFreshTTL),
// Bad is suppressed to Unknown.  A peer that recently sent us an inbound message
// is demonstrably alive; the reply path (back to their source address) is
// available via the active NAT mapping, so treating them as fully unreachable
// would discard a working path and waste the inbound evidence.
func (n *Node) PeerHealthOf(id a2al.NodeID) PeerHealthState {
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	var v4InboundAt, v6InboundAt time.Time
	if e != nil {
		v4InboundAt = e.v4.lastInboundAt
		v6InboundAt = e.v6.lastInboundAt
	}
	n.healthMu.RUnlock()
	if e == nil {
		return PeerHealthUnknown
	}
	v4s := familyHealthState(&e.v4)
	v6s := familyHealthState(&e.v6)

	// Any Good → Good.
	if v4s == PeerHealthGood || v6s == PeerHealthGood {
		return PeerHealthGood
	}
	// Collect active (ever-used) families.
	if !e.v4.everUsed && !e.v6.everUsed {
		return PeerHealthUnknown
	}
	// All active families must be Bad to declare the peer Bad.
	if e.v4.everUsed && v4s != PeerHealthBad {
		return PeerHealthUnknown
	}
	if e.v6.everUsed && v6s != PeerHealthBad {
		return PeerHealthUnknown
	}
	// Fresh inbound on any family: the peer is demonstrably alive and the
	// reply path via the active NAT mapping is available.  Suppress Bad →
	// Unknown so this peer is not dropped from tabNearestHealthy or the
	// query engine's Good/Unknown tracks.
	now := time.Now()
	if now.Sub(v4InboundAt) < lastInboundFreshTTL || now.Sub(v6InboundAt) < lastInboundFreshTTL {
		return PeerHealthUnknown
	}
	return PeerHealthBad
}

// IsPunching reports whether an ICE hole-punch attempt is currently in flight
// for the given peer. Used by the query engine's addCand to exclude punching
// nodes from all track slots (§12 of strategy doc).
func (n *Node) IsPunching(id a2al.NodeID) bool {
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	return e != nil && e.isPunching
}

// tabNearestHealthy returns up to k routing-table peers sorted first by
// health state (Good → Unknown → Bad) and then by XOR distance within each
// group.  This ensures StoreAt and query seeds prefer known-reachable nodes.
//
// Scan width: routing.K*4 instead of routing.K.  The wider scan ensures that
// reachable (Good/Unknown) nodes are always included in the candidate pool
// even when unreachable (Bad) peers happen to be XOR-closer to the target.
// An unreachable peer's effective distance is infinite, so it must not beat
// a reachable peer simply by having a smaller XOR value.  In large networks
// the extra overhead is negligible; in small networks it is essential.
func (n *Node) tabNearestHealthy(target a2al.NodeID, k int) []protocol.NodeInfo {
	all := n.tabNearest(target, routing.K*4)
	var good, unknown, bad []protocol.NodeInfo
	for _, ni := range all {
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		switch n.PeerHealthOf(id) {
		case PeerHealthGood:
			good = append(good, ni)
		case PeerHealthBad:
			bad = append(bad, ni)
		default:
			unknown = append(unknown, ni)
		}
	}
	// tabNearest already returns nodes in XOR-ascending order; splitting into
	// groups preserves that relative order within each group.
	result := make([]protocol.NodeInfo, 0, len(all))
	result = append(result, good...)
	result = append(result, unknown...)
	result = append(result, bad...)
	if len(result) > k {
		result = result[:k]
	}
	return result
}

// recordPeerSeen updates last_seen for nid and increments seenUniqueSinceBoot
// the first time this process observes nid via tabAdd (not via loadSeenPeers).
func (n *Node) recordPeerSeen(nid a2al.NodeID) {
	now := time.Now()
	_, loaded := n.seenThisBoot.LoadOrStore(nid, struct{}{})
	if !loaded {
		n.seenUniqueSinceBoot.Add(1)
	}
	n.seenPeers.Store(nid, now)
}

// reachCounts counts unique peers whose last_seen falls within 1h, 24h, and 7d.
// Entries older than 7d are pruned during this scan (lazy cleanup).
func (n *Node) reachCounts() (r1h, r24h, r7d int) {
	now := time.Now()
	cutoff7d := now.Add(-7 * 24 * time.Hour)
	cutoff24h := now.Add(-24 * time.Hour)
	cutoff1h := now.Add(-1 * time.Hour)
	var toDelete []any
	n.seenPeers.Range(func(k, v any) bool {
		t := v.(time.Time)
		if t.Before(cutoff7d) {
			toDelete = append(toDelete, k)
			return true
		}
		r7d++
		if !t.Before(cutoff24h) {
			r24h++
		}
		if !t.Before(cutoff1h) {
			r1h++
		}
		return true
	})
	for _, k := range toDelete {
		n.seenPeers.Delete(k)
	}
	return
}

// EstimatedNetworkSize returns the bucket-density estimate of the current
// number of active nodes in the DHT (includes all nodes; for freshness-filtered
// estimate use EstimatedNetworkSizeFiltered).
func (n *Node) EstimatedNetworkSize() int { return n.tabEstimatedNetworkSize() }

// tabEstimatedNetworkSize returns the bucket-density estimate of network size.
func (n *Node) tabEstimatedNetworkSize() int {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.EstimatedNetworkSize()
}

// EstimatedNetworkSizeFiltered returns the network size estimate restricted to
// nodes verified within the past 30 minutes, along with a confidence score in
// [0, 1].  Higher confidence means more sample buckets contributed to the median.
func (n *Node) EstimatedNetworkSizeFiltered(cutoff time.Time) (int, float64) {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.EstimatedNetworkSizeFiltered(cutoff)
}

// absorbNodeInfo merges a contact into the routing table (hearsay path) and,
// when IP:port looks usable, registers the UDP dial address.
// learnedFrom is the NodeID of the peer whose FIND_NODE response included ni
// (zero value if the source is unknown or it is a local routing-table seed).
//
// For XOR-close hearsay nodes (bucket ≥ hearsayProbeBucketThreshold) that have
// never been contacted before, a single opportunistic PING is fired in the
// background.  This is fire-and-forget: no retry on failure, no removal from the
// routing table on failure.  Success promotes the entry to verified via the
// normal recordSuccess path.
func (n *Node) absorbNodeInfo(ni protocol.NodeInfo, learnedFrom a2al.NodeID) {
	meta := routing.EntryMeta{LearnedFrom: learnedFrom} // VerifiedAt zero = hearsay
	n.tabAdd(ni, meta, nil)
	if ni.Port == 0 || (len(ni.IP) != 4 && len(ni.IP) != 16) {
		return
	}
	var id a2al.NodeID
	if len(ni.NodeID) != len(id) {
		return
	}
	copy(id[:], ni.NodeID)
	udp := &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
	n.bindPeerLive(id, udp, rankHearsay)

	// When ni.IP is a v4 address (typical: FIND_NODE response adapted for a v4
	// asker), also absorb the peer's v6 address from its EndpointRecord if we
	// have one locally. This prevents peerAddrs.v6 from staying empty for
	// dual-stack peers discovered only through v4 FIND_NODE exchanges.
	if udp.IP.To4() != nil {
		if v6addr := n.advertisedStableAddr(id, true); v6addr != nil {
			n.bindPeerLive(id, v6addr, rankHearsay)
		}
	}

	// Opportunistic single probe for routing-critical hearsay nodes.
	if routing.BucketIndex(n.nid, id) >= hearsayProbeBucketThreshold {
		n.healthMu.RLock()
		hasHistory := n.health[nodeIDKey(id)] != nil
		n.healthMu.RUnlock()
		if !hasHistory {
			addr := udp // capture for goroutine
			go func() {
				pctx, cancel := context.WithTimeout(n.ctx, rpcAttemptTimeout)
				defer cancel()
				n.PingIdentity(pctx, addr) //nolint:errcheck — fire-and-forget
			}()
		}
	}
}

func (n *Node) bindPeerLive(id a2al.NodeID, addr net.Addr, rank addrRank) {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	if pa == nil {
		pa = &peerAddrs{}
		n.peers[nodeIDKey(id)] = pa
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		pa.tryLive(udp, rank)
	} else {
		pa.fallback = addr
	}
	n.peerMu.Unlock()
	n.addrToID.Store(addr.String(), id)
}

// BindPeerAddr registers a Verified live dial address.
// Deprecated: prefer NotePeerDialSuccess which additionally updates health counters.
// Retained for test helpers and internal callers that do not have RTT information.
func (n *Node) BindPeerAddr(id a2al.NodeID, addr net.Addr) {
	n.bindPeerLive(id, addr, rankVerified)
}

// NotePeerDialSuccess records a verified direct connection (e.g. QUIC handshake)
// to addr from the upper-layer transport.  It updates both the live address slot
// and the health counters — equivalent in effect to a successful DHT RPC, allowing
// a peer that was in Bad state to recover without waiting for a UDP round-trip.
//
// addr should be the actual remote address observed on the connection
// (e.g. conn.RemoteAddr()), which may differ from the dialled address due to NAT.
// rtt is the round-trip time of the handshake; pass 0 if unknown.
func (n *Node) NotePeerDialSuccess(id a2al.NodeID, addr net.Addr, rtt time.Duration) {
	n.recordSuccess(id, addr, rtt)
}

// NotePeerDialFailure records a failed direct connection attempt to addr.
// It is a hint to the health subsystem that this address is not currently
// reachable via the upper-layer transport.
//
// Callers MUST only invoke this for genuine transport failures, not for context
// cancellations caused by a competing dial winning (happy eyeballs).
func (n *Node) NotePeerDialFailure(id a2al.NodeID, addr net.Addr) {
	n.recordFailure(id, addr)
}

// BindPeerAnchor registers a long-lived advertised/infra dial address.
// Anchor is never overwritten by hearsay or ephemeral sources.
func (n *Node) BindPeerAnchor(id a2al.NodeID, addr net.Addr) {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	if pa == nil {
		pa = &peerAddrs{}
		n.peers[nodeIDKey(id)] = pa
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		pa.tryAnchor(udp)
	} else {
		pa.fallback = addr
	}
	n.peerMu.Unlock()
	n.addrToID.Store(addr.String(), id)
}

// SetSelfExtIP records our own public IPv4 (from STUN/HTTP probe). Used to detect
// NAT hairpin peers: nodes behind the same NAT share the same public IP and
// typically cannot reach each other via that IP (router hairpinning not supported).
func (n *Node) SetSelfExtIP(ip net.IP) {
	n.selfExtMu.Lock()
	n.selfExtIP = ip
	n.selfExtMu.Unlock()
}

// SetSelfExtIPv6 records our own public IPv6 GUA (from STUN/HTTP probe).
// Unlike the v4 counterpart this is not used for hairpin detection (v6 GUA
// nodes are directly reachable); it is used to self-identify when the node's
// v6 address appears in the well-known DNS list.
func (n *Node) SetSelfExtIPv6(ip net.IP) {
	n.selfExtMu.Lock()
	n.selfExtIPv6 = ip
	n.selfExtMu.Unlock()
}

// SelfExtIPv6 returns the node's public IPv6 GUA set via SetSelfExtIPv6.
func (n *Node) SelfExtIPv6() net.IP {
	n.selfExtMu.RLock()
	defer n.selfExtMu.RUnlock()
	return n.selfExtIPv6
}

// isSelfReflectedAddr reports whether addr is our own bound transport address
// (NAT loopback / self-reflected UDP source).
func (n *Node) isSelfReflectedAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	self := n.tr.LocalAddr()
	if self == nil {
		return false
	}
	su, ok1 := addr.(*net.UDPAddr)
	sl, ok2 := self.(*net.UDPAddr)
	if !ok1 || !ok2 {
		return addr.String() == self.String()
	}
	return su.IP.Equal(sl.IP) && su.Port == sl.Port
}

// isUnusableControlPlaneReachAddr reports addresses that must not be used for
// DHT control-plane reachability learning or outbound selection (hairpin NAT
// reflection, self bind address). Does not apply to Mode A business paths.
func (n *Node) isUnusableControlPlaneReachAddr(addr net.Addr) bool {
	return n.isHairpinAddr(addr) || n.isSelfReflectedAddr(addr)
}

// isControlPlaneSelfExcitation reports inbound evidence that must not drive
// lastInbound recording or ICE punch triggers on the DHT control plane.
func (n *Node) isControlPlaneSelfExcitation(peerID a2al.NodeID, from net.Addr) bool {
	if peerID == n.nid {
		return true
	}
	return n.isUnusableControlPlaneReachAddr(from)
}

// isHairpinAddr returns true when addr shares our public IP but is not our own
// port — a strong signal that sending to it requires NAT hairpinning.
func (n *Node) isHairpinAddr(addr net.Addr) bool {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}
	n.selfExtMu.RLock()
	ext := n.selfExtIP
	n.selfExtMu.RUnlock()
	if ext == nil {
		return false
	}
	if !ext.Equal(udp.IP) {
		return false
	}
	// Same IP but different port → another node behind the same NAT.
	// Same IP + same port → our own reflected address, not a peer.
	self := n.tr.LocalAddr()
	if selfUDP, ok := self.(*net.UDPAddr); ok && selfUDP.Port == udp.Port {
		return false
	}
	return true
}

func (n *Node) reply(from net.Addr, ch inboundChannel, req *protocol.DecodedMessage, msgType uint8, body any) {
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: msgType,
		TxID:    append([]byte(nil), req.Header.TxID...),
	}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
	if err != nil {
		n.log.Warn("dht reply marshal failed", "msg_type", msgType, "to", from, "err", err)
		if errors.Is(err, protocol.ErrInvalidMessage) {
			var nodes []protocol.NodeInfo
			switch b := body.(type) {
			case *protocol.BodyFindNodeResp:
				nodes = b.Nodes
			case *protocol.BodyFindValueResp:
				nodes = b.Nodes
			}
			for i, ni := range nodes {
				if len(ni.IP) != 4 && len(ni.IP) != 16 {
					var nid a2al.NodeID
					copy(nid[:], ni.NodeID)
					n.log.Debug("dht reply: bad node ip", "idx", i, "node", nid, "ip_len", len(ni.IP))
					break
				}
				if len(ni.Address) != len(a2al.Address{}) || len(ni.NodeID) != len(a2al.NodeID{}) {
					n.log.Debug("dht reply: bad node lengths", "idx", i, "addr_len", len(ni.Address), "nid_len", len(ni.NodeID))
					break
				}
			}
		}
		return
	}
	if err := n.replyVia(from, ch, req, raw); err != nil {
		n.log.Warn("dht reply send failed", "msg_type", msgType, "to", from, "size", len(raw), "err", err)
	} else {
		n.statsTx.Add(1)
	}
}

// replyVia sends a response back along the exact channel and source the request
// arrived on. The reverse path is already proven reachable by the inbound packet,
// so replies are faithful to it and never consult outboundPlan (anchor / health /
// skip-cold selection), which is reserved for actively-initiated RPCs.
//
//   - inboundChannelQUIC: reply over the same Mode B control-plane connection
//     (keyed by NodeID); if it dropped meanwhile, fall back to the UDP source.
//   - inboundChannelUDP: reply verbatim to the datagram source.
func (n *Node) replyVia(from net.Addr, ch inboundChannel, req *protocol.DecodedMessage, raw []byte) error {
	if ch == inboundChannelQUIC && n.punch != nil {
		peerID := a2al.NodeIDFromAddress(req.SenderAddr)
		if sent, err := n.punch.SendTo(n.ctx, peerID, raw); sent {
			return err
		}
		// Mode B connection gone between receive and reply: fall back to UDP source.
	}
	return n.tr.Send(from, raw)
}

func (n *Node) onPing(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, ch, dec)
	body := &protocol.BodyPong{
		Address:      n.addr[:],
		ObservedAddr: ObservedAddr(from),
	}
	n.reply(from, ch, dec, protocol.MsgPong, body)
}

func (n *Node) onFindNode(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, ch, dec)
	target := dec.Body.(*protocol.BodyFindNode).Target
	var tid a2al.NodeID
	copy(tid[:], target)
	resp := &protocol.BodyFindNodeResp{
		Nodes:        n.adaptNodeListForAsker(n.tabNearestHealthy(tid, routing.K), from),
		ObservedAddr: ObservedAddr(from),
	}
	for len(resp.Nodes) > 1 {
		sz, err := protocol.FindNodeResponseWireSize(resp)
		if err != nil || sz <= maxResponsePayload {
			break
		}
		resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
	}
	n.reply(from, ch, dec, protocol.MsgFindNodeResp, resp)
}

func (n *Node) onFindValue(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, ch, dec)
	body := dec.Body.(*protocol.BodyFindValue)
	var tid a2al.NodeID
	copy(tid[:], body.Target)
	now := time.Now()
	records := n.store.GetAll(tid, body.RecType, now)
	best := n.store.Get(tid, now)
	resp := &protocol.BodyFindValueResp{
		Nodes:        n.adaptNodeListForAsker(n.tabNearestHealthy(tid, routing.K), from),
		ObservedAddr: ObservedAddr(from),
		Records:      records,
	}
	// Populate the legacy Record field only when Records is empty: receivers
	// that understand the Records array prefer it over Record, so including
	// both fields for the same content doubles the packet size for no benefit.
	// Setting Record solely for older nodes that only read the legacy field.
	if best != nil && len(records) == 0 && (body.RecType == 0 || best.RecType == body.RecType) {
		r := *best
		resp.Record = &r
	}
	for {
		sz, err := protocol.FindValueResponseWireSize(resp)
		if err != nil || sz <= maxResponsePayload {
			break
		}
		if len(resp.Nodes) > 1 {
			resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
			continue
		}
		// Drop the oldest record (index 0) to preserve newer records for the
		// requester. GetAll returns records in insertion order (oldest first).
		if len(resp.Records) > 1 {
			resp.Records = resp.Records[1:]
			continue
		}
		// Last resort: clear the legacy Record field. Its content is already
		// carried in Records[0] when both were set; if Records is empty and
		// a single record still exceeds the limit, drop it rather than send
		// a packet that would be silently discarded by the UDP transport.
		if resp.Record != nil {
			resp.Record = nil
			continue
		}
		break
	}
	hasRecords := len(resp.Records) > 0 || resp.Record != nil
	if hasRecords {
		n.statsFindValueServed.Add(1)
	}
	n.reply(from, ch, dec, protocol.MsgFindValueResp, resp)

	// Register oneShot subscription only when this node confirmed it holds records
	// (proven valid neighbor principle: §4.2). Nodes that returned nothing are
	// not in the hot STORE path and would produce dead pushes.
	if body.OneShotSubscribe && hasRecords {
		if udpAddr, ok := from.(*net.UDPAddr); ok && udpAddr != nil {
			n.store.AddOneShotSub(tid, *udpAddr)
		}
	}
}

func (n *Node) onStore(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, ch, dec)
	body := dec.Body.(*protocol.BodyStore)
	var key a2al.NodeID
	if len(body.Key) == len(key) {
		copy(key[:], body.Key)
	}
	// Pre-check: for sovereign records, record whether the slot is already
	// occupied before the Put so we can avoid arming soft expiry on existing
	// legitimate replica members (cross-contamination guard, Direction B).
	var sovereignSlotOccupied bool
	if protocol.RecordCategory(body.Record.RecType) == protocol.CategorySovereign {
		ck := key
		if ck == (a2al.NodeID{}) {
			ck = recordKeyForSigned(body.Record)
		}
		sovereignSlotOccupied = len(n.store.GetAll(ck, body.Record.RecType, time.Now())) > 0
	}

	err := n.store.Put(key, body.Record, time.Now())
	alreadyHad := errors.Is(err, ErrStaleRecord)
	ok := err == nil || alreadyHad
	if ok {
		n.statsStoreRx.Add(1)
	}
	var reason protocol.StoreReason
	if !ok {
		if errors.Is(err, ErrStorePolicy) {
			reason = protocol.StoreReasonPolicy
		} else {
			reason = protocol.StoreReasonRecordInvalid
		}
		n.log.Debug("store rejected", "from", from, "key", hex.EncodeToString(key[:4]), "reason", reason, "err", err)
	}
	n.reply(from, ch, dec, protocol.MsgStoreResp, &protocol.BodyStoreResp{Stored: ok, AlreadyHad: alreadyHad, Reason: reason})

	// Deliver DHT_PUSH to all one-shot subscribers for this key.
	// Only fires on genuinely new records (not already-had / rejected).
	if err == nil {
		n.dispatchDHTPush(key, body.Record)
	}

	// Path-cache registration for sovereign records (Direction B).
	// Distinguish publisher's direct StoreAt from a querier's path-cache StoreAt
	// by comparing the sender's NodeID with the record's publisher NodeID.
	//   Publisher's STORE → clear soft expiry (record is now authoritative here).
	//   Querier's STORE   → set soft expiry + async register with publisher so
	//                       this node enters publisher's repSet for future updates.
	if (err == nil || alreadyHad) && protocol.RecordCategory(body.Record.RecType) == protocol.CategorySovereign {
		senderID := a2al.NodeIDFromAddress(dec.SenderAddr)
		publisherID := recordKeyForSigned(body.Record)
		storeKey := key
		if storeKey == (a2al.NodeID{}) {
			storeKey = publisherID
		}
		if senderID == publisherID {
			n.store.ClearSoftExpiry(storeKey, body.Record.RecType)
		} else if err == nil && !sovereignSlotOccupied {
			// Freshly stored path-cached record into an empty slot: arm soft
			// expiry and try to register with publisher so they can push future
			// updates here.  Skip if the slot already had a record to avoid
			// cross-contaminating legitimate repSet members with soft expiry.
			n.store.SetSoftExpiry(storeKey, body.Record.RecType, time.Now().Add(pathCacheSoftTTL))
			rec := body.Record
			go n.registerWithPublisher(storeKey, rec)
		}
	}
}

// registerWithPublisher sends a FindNode RPC directly to the record's publisher.
// Receiving the RPC causes the publisher to add this node to its routing table,
// so future renewBackground calls will discover this node and include it in
// storeAndRecord — eventually promoting it to a full repSet member.
// On success the soft expiry is cleared; if unreachable the expiry fires naturally.
func (n *Node) registerWithPublisher(storeKey a2al.NodeID, rec protocol.SignedRecord) {
	publisherID := recordKeyForSigned(rec)
	addr, ok := n.lookupPeerHealthAware(publisherID)
	if !ok {
		addr, ok = n.lookupPeer(publisherID)
	}
	if !ok {
		return // publisher not in routing table; soft expiry will handle cleanup
	}
	ctx, cancel := context.WithTimeout(n.ctx, queryPeerTimeout)
	defer cancel()
	if _, err := n.FindNode(ctx, addr, storeKey); err != nil {
		return // publisher unreachable; soft expiry stays
	}
	// FindNode succeeded: publisher has added this node to its routing table.
	// Clear the soft expiry — the publisher's next renewBackground will push the
	// latest record here, confirming this node as part of the authoritative repSet.
	n.store.ClearSoftExpiry(storeKey, rec.RecType)
}

// dispatchDHTPush delivers a newly stored record to all oneShot subscribers via MsgDHTPush.
// Each subscriber goroutine uses sendAndWait; ACK with OneShotSubscribe=true renews the sub.
func (n *Node) dispatchDHTPush(key a2al.NodeID, rec protocol.SignedRecord) {
	subs := n.store.ConsumeOneShotSubs(key)
	for _, sub := range subs {
		sub := sub // capture
		go n.pushToSubscriber(key, rec, sub)
	}
}

// pushToSubscriber sends MsgDHTPush to one subscriber and processes the ACK.
func (n *Node) pushToSubscriber(key a2al.NodeID, rec protocol.SignedRecord, sub oneShotSub) {
	ctx, cancel := context.WithTimeout(n.ctx, 2*time.Second)
	defer cancel()
	addr := sub.addr
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgDHTPush}
	body := &protocol.BodyDHTPush{Key: key[:], Record: rec}
	dec, _, err := n.sendAndWait(ctx, &addr, hdr, body, protocol.MsgDHTPushACK)
	if err != nil {
		n.log.Debug("dht_push: failed", "dst", addr.String(), "err", err)
		return
	}
	ack := dec.Body.(*protocol.BodyDHTPushACK)
	if ack.OneShotSubscribe {
		// Recipient accepted the record as new → renew subscription for next delivery.
		n.store.AddOneShotSub(key, addr)
	}
}

// onDHTPush handles an incoming MsgDHTPush (this node is the subscriber / daemon).
func (n *Node) onDHTPush(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	body := dec.Body.(*protocol.BodyDHTPush)
	var key a2al.NodeID
	copy(key[:], body.Key)

	resubscribe := false
	n.pushMu.RLock()
	h := n.pushHandler
	n.pushMu.RUnlock()
	if h != nil {
		resubscribe = h(key, body.Record)
	}

	msgID := sha256.Sum256(body.Record.Payload)
	n.reply(from, ch, dec, protocol.MsgDHTPushACK, &protocol.BodyDHTPushACK{
		Key:              key[:],
		MsgID:            msgID[:],
		OneShotSubscribe: resubscribe,
	})
}

// SetPushHandler registers fn as the handler for incoming MsgDHTPush messages.
// fn(key, record) should return true if the record was new (causing ACK to renew
// the subscription). Thread-safe; can be called at any time.
func (n *Node) SetPushHandler(fn func(key a2al.NodeID, rec protocol.SignedRecord) bool) {
	n.pushMu.Lock()
	n.pushHandler = fn
	n.pushMu.Unlock()
}

// natProbeEchoMax is the maximum number of NAT probe echoes sent per source IP
// per 10-second window.  Because ClaimedAddr.IP must equal the requester's source
// IP (see below), this is effectively a per-peer cap.
const natProbeEchoMax = 3

// onNATProbeReq handles an incoming NATProbeReq: validates the claimed address,
// enforces source-IP consistency (anti-reflection), applies a per-source rate
// limit, then sends a NATProbeEcho directly to that address.
// Old nodes never reach here (VerifyAndDecode returns ErrUnknownMsgType for 0x09).
func (n *Node) onNATProbeReq(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, ch, dec)
	body := dec.Body.(*protocol.BodyNATProbeReq)

	host, port, ok := protocol.ParseObservedUDP(body.ClaimedAddr)
	if !ok {
		return
	}
	ip := net.ParseIP(host)
	if !protocol.IsPublicIP(ip) {
		return // reject private/loopback claimed addresses
	}

	// ClaimedAddr.IP must match the UDP source IP of the request.
	// This ensures a peer can only trigger echoes to its own address,
	// eliminating cross-IP reflection abuse while still supporting any claimed port.
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok || !ip.Equal(fromUDP.IP) {
		return
	}

	// Per-source-IP rate limit. Normalize the key so that an IPv4-mapped IPv6
	// address (::ffff:x.x.x.x) and its plain IPv4 form share the same bucket,
	// preventing a dual-stack sender from doubling its echo budget.
	rateKey := fromUDP.IP.String()
	if v4 := fromUDP.IP.To4(); v4 != nil {
		rateKey = v4.String()
	}
	if !n.echoRateOK(rateKey) {
		return
	}

	target := &net.UDPAddr{IP: ip, Port: int(port)}
	txID := make([]byte, 20)
	if _, err := crand.Read(txID); err != nil {
		return
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgNATProbeEcho, TxID: txID}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, &protocol.BodyNATProbeEcho{Token: body.Token}, n.ks, n.addr)
	if err != nil {
		return
	}
	_ = n.tr.Send(target, raw)
	n.statsTx.Add(1)
}

// echoRateOK returns true and increments the per-source counter if the source IP
// is within its echo budget (natProbeEchoMax per 10 s).  Expired windows reset.
func (n *Node) echoRateOK(srcIP string) bool {
	n.natProbeEchoMu.Lock()
	defer n.natProbeEchoMu.Unlock()
	now := time.Now()
	e := n.natProbeEchoMap[srcIP]
	if e == nil || now.After(e.windowEnd) {
		n.natProbeEchoMap[srcIP] = &probeEchoEntry{windowEnd: now.Add(10 * time.Second), count: 1}
		return true
	}
	e.count++
	return e.count <= natProbeEchoMax
}

// onNATProbeEcho receives an echo from a peer and notifies any waiter registered for the token.
func (n *Node) onNATProbeEcho(from net.Addr, inCh inboundChannel, dec *protocol.DecodedMessage) {
	n.remember(from, inCh, dec)
	body := dec.Body.(*protocol.BodyNATProbeEcho)
	key := hex.EncodeToString(body.Token)
	n.natProbeMu.Lock()
	waitCh, ok := n.natProbeWait[key]
	n.natProbeMu.Unlock()
	if ok {
		select {
		case waitCh <- struct{}{}:
		default:
		}
	}
}

// SendNATProbeReq asks probeAddr to send a NATProbeEcho to claimedAddr.
// claimedAddr is the wire-encoded public UDP address (6 or 18 bytes).
// Returns true if an echo arrived within the context deadline, nil error on timeout.
func (n *Node) SendNATProbeReq(ctx context.Context, probeAddr net.Addr, claimedAddr []byte) (bool, error) {
	token := make([]byte, 8)
	if _, err := crand.Read(token); err != nil {
		return false, err
	}
	key := hex.EncodeToString(token)
	ch := make(chan struct{}, 1)

	n.natProbeMu.Lock()
	n.natProbeWait[key] = ch
	n.natProbeMu.Unlock()
	defer func() {
		n.natProbeMu.Lock()
		delete(n.natProbeWait, key)
		n.natProbeMu.Unlock()
	}()

	txID := make([]byte, 20)
	if _, err := crand.Read(txID); err != nil {
		return false, err
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgNATProbeReq, TxID: txID}
	body := &protocol.BodyNATProbeReq{Token: token, ClaimedAddr: claimedAddr}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
	if err != nil {
		return false, err
	}
	if err := n.tr.Send(probeAddr, raw); err != nil {
		return false, err
	}
	n.statsTx.Add(1)

	select {
	case <-ch:
		return true, nil
	case <-ctx.Done():
		return false, nil
	case <-n.ctx.Done():
		return false, n.ctx.Err()
	}
}

// rpcAttemptTimeout is the per-attempt deadline for a single UDP RPC round-trip.
// rpcMaxAttempts is the number of retries on timeout (total = attempts × timeout = 15 s).
const (
	rpcAttemptTimeout = 5 * time.Second
	rpcMaxAttempts    = 3
)

// maxResponsePayload is the maximum CBOR body size for response messages sent via reply().
// wireOuter overhead: Header≈30 B + SenderPubkey(32+2)=34 B + Signature(64+2)=66 B +
// bstr frame(3) + map/key framing(5) ≈ 138 B total.
// 1200 (MaxPacketSize) - 138 (overhead) - 12 (safety margin) = 1050.
const maxResponsePayload = 1050

func (n *Node) sendAndWait(ctx context.Context, to net.Addr, hdr protocol.Header, body any, expect uint8) (*protocol.DecodedMessage, deliverMeta, error) {
	var lastMeta deliverMeta
	for attempt := 0; attempt < rpcMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, lastMeta, ctx.Err()
		}
		// Fresh TxID per attempt to avoid stale-response cross-matching.
		hdr.TxID = make([]byte, 20)
		if _, err := crand.Read(hdr.TxID); err != nil {
			return nil, lastMeta, err
		}
		ch := n.registerWait(hdr.TxID, expect)
		raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
		if err != nil {
			n.unregisterWait(hdr.TxID)
			return nil, lastMeta, err
		}
		peerID, _ := n.lookupPeerID(to)
		meta, err := n.deliver(ctx, peerID, to, raw)
		lastMeta = meta
		if err != nil {
			n.unregisterWait(hdr.TxID)
			return nil, lastMeta, err
		}
		n.statsTx.Add(1)

		aCtx, aCancel := context.WithTimeout(ctx, rpcAttemptTimeout)
		select {
		case dec := <-ch:
			aCancel()
			n.statsRPC.Add(1)
			return dec, lastMeta, nil
		case <-aCtx.Done():
			n.unregisterWait(hdr.TxID)
			aCancel()
			if n.ctx.Err() != nil {
				return nil, lastMeta, n.ctx.Err()
			}
			// QUIC RPC timed out (no response within window): evict the connection
			// regardless of whether the caller's ctx has also expired.  The next
			// outboundPlan call will see HasConn=false and fall back to UDP or
			// trigger re-punch.  Without this, a short outer deadline (e.g.
			// queryPeerTimeout=2s < rpcAttemptTimeout=5s) causes ctx.Err() to
			// fire first, skipping the eviction and leaving a stale conn in the
			// pool that HasConn keeps selecting on every subsequent cycle.
			if lastMeta.viaQUIC && n.punch != nil {
				if peerID, ok := n.lookupPeerID(to); ok {
					n.punch.InvalidateConn(peerID)
				}
			}
			if ctx.Err() != nil {
				return nil, lastMeta, ctx.Err()
			}
			n.log.Debug("dht rpc timeout, retrying", "to", to, "msg_type", hdr.MsgType, "attempt", attempt+1)
			// per-attempt timeout; retry
		case <-n.ctx.Done():
			n.unregisterWait(hdr.TxID)
			aCancel()
			return nil, lastMeta, n.ctx.Err()
		}
	}
	n.log.Warn("dht rpc failed after retries",
		"to", to,
		"msg_type", hdr.MsgType,
		"attempts", rpcMaxAttempts,
		"dial_addr", lastMeta.dialAddr,
		"via_quic", lastMeta.viaQUIC,
		"plan_reason", lastMeta.reason,
	)
	return nil, lastMeta, context.DeadlineExceeded
}

// sendToOrFallback delivers raw to the peer at addr via the L0 legacy path.
// Tests and NAT-probe-adjacent callers use this directly; RPC paths go through deliver.
func (n *Node) sendToOrFallback(ctx context.Context, to net.Addr, raw []byte) error {
	return n.sendToOrFallbackLegacy(ctx, to, raw)
}

func (n *Node) notifyObserved(reporter a2al.NodeID, wire []byte) {
	if n.onObservedAddr != nil && len(wire) > 0 {
		n.onObservedAddr(reporter, wire)
	}
}

// PeerIdentity holds the identity extracted from a PONG response.
type PeerIdentity struct {
	Address      a2al.Address
	NodeID       a2al.NodeID
	ObservedWire []byte // BodyPong.observed_addr (how reporter sees us); may be nil
}

// Ping sends PING and waits for PONG. Start() must be running.
func (n *Node) Ping(ctx context.Context, peer net.Addr) error {
	_, err := n.PingIdentity(ctx, peer)
	return err
}

// PingIdentity sends PING, waits for PONG, and returns the remote peer's identity extracted from the response. The peer is automatically registered into the routing table and dial address map.
func (n *Node) PingIdentity(ctx context.Context, peer net.Addr) (*PeerIdentity, error) {
	tx := make([]byte, 20)
	if _, err := crand.Read(tx); err != nil {
		return nil, err
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgPing, TxID: tx}
	body := &protocol.BodyPing{Address: n.addr[:]}
	t0 := time.Now()
	dec, meta, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgPong)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok && !meta.viaQUIC {
			// Penalise the address family actually used for the attempt (meta.dialAddr),
			// not necessarily the caller's stable addr hint.
			failAddr := meta.dialAddr
			if failAddr == nil {
				failAddr = peer
			}
			n.recordFailure(id, failAddr)
		}
		return nil, err
	}
	pong, ok := dec.Body.(*protocol.BodyPong)
	if !ok {
		return nil, errors.New("dht: expected PONG")
	}
	peerAddr := dec.SenderAddr
	peerNID := a2al.NodeIDFromAddress(peerAddr)
	n.recordSuccess(peerNID, successDialAddr(peer, meta), time.Since(t0))
	ni := nodeInfoFromMessage(dec, peer)
	n.BindPeerAddr(peerNID, peer)
	n.tabAdd(ni, routing.EntryMeta{VerifiedAt: time.Now()}, peer)
	var obs []byte
	if len(pong.ObservedAddr) > 0 {
		obs = append([]byte(nil), pong.ObservedAddr...)
	}
	n.notifyObserved(peerNID, obs)
	return &PeerIdentity{Address: peerAddr, NodeID: peerNID, ObservedWire: obs}, nil
}

// StoreAt sends STORE to peer. storeKey zero omits BodyStore.Key (receiver derives key from rec.Address).
// On success peerID is the remote node's identity from the STORE response.
// meta describes the outbound path actually used (for diagnostic logging).
func (n *Node) StoreAt(ctx context.Context, peer net.Addr, storeKey a2al.NodeID, rec protocol.SignedRecord) (stored bool, peerID a2al.NodeID, meta deliverMeta, err error) {
	body := &protocol.BodyStore{Record: rec}
	if storeKey != (a2al.NodeID{}) {
		body.Key = storeKey[:]
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgStore}
	t0 := time.Now()
	dec, meta, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgStoreResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok && !meta.viaQUIC {
			// Penalise the address family actually used for the attempt (meta.dialAddr),
			// not necessarily the caller's stable addr hint.
			failAddr := meta.dialAddr
			if failAddr == nil {
				failAddr = peer
			}
			n.recordFailure(id, failAddr)
		}
		return false, a2al.NodeID{}, meta, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	dial := successDialAddr(peer, meta)
	n.recordSuccess(peerNID, dial, time.Since(t0))
	n.rememberStoreSuccess(peerNID, dial)
	resp := dec.Body.(*protocol.BodyStoreResp)
	switch {
	case resp.AlreadyHad:
		n.log.Debug("dht store: peer already had record", "peer", peer, "key", hex.EncodeToString(storeKey[:4]))
	case !resp.Stored && resp.Reason == protocol.StoreReasonPolicy:
		n.log.Debug("dht store: peer policy rejected", "peer", peer, "key", hex.EncodeToString(storeKey[:4]))
	case !resp.Stored && resp.Reason == protocol.StoreReasonRecordInvalid:
		n.log.Debug("dht store: record invalid", "peer", peer, "key", hex.EncodeToString(storeKey[:4]))
	}
	return resp.Stored, peerNID, meta, nil
}

// rememberStoreSuccess registers dial→nodeID mapping after a successful outbound
// STORE. Anchor binding is handled by tabAdd (UDP inbound) or explicit beacon paths;
// do not write Anchor here from outbound dial evidence alone.
func (n *Node) rememberStoreSuccess(id a2al.NodeID, dial net.Addr) {
	if dial == nil {
		return
	}
	n.addrToID.Store(dial.String(), id)
}

// FindNode asks peer for closest nodes to target NodeID.
func (n *Node) FindNode(ctx context.Context, peer net.Addr, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindNode}
	body := &protocol.BodyFindNode{Target: target[:]}
	t0 := time.Now()
	dec, meta, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindNodeResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok && !meta.viaQUIC {
			// Penalise the address family actually used for the attempt (meta.dialAddr),
			// not necessarily the caller's stable addr hint.
			failAddr := meta.dialAddr
			if failAddr == nil {
				failAddr = peer
			}
			n.recordFailure(id, failAddr)
		}
		return nil, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.recordSuccess(peerNID, successDialAddr(peer, meta), time.Since(t0))
	br := dec.Body.(*protocol.BodyFindNodeResp)
	n.notifyObserved(peerNID, br.ObservedAddr)
	return br.Nodes, nil
}

// FindValueWithNodes queries peer. recType 0 requests all record types in the response.
// subscribe=true sets OneShotSubscribe in the request, asking the peer to push future records.
// Only pass subscribe=true in AggregateRecords mode (not point-in-time FindRecords lookups).
func (n *Node) FindValueWithNodes(ctx context.Context, peer net.Addr, key a2al.NodeID, recType uint8, subscribe bool) ([]protocol.SignedRecord, []protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindValue}
	body := &protocol.BodyFindValue{Target: key[:], RecType: recType, OneShotSubscribe: subscribe}
	t0 := time.Now()
	dec, meta, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindValueResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok && !meta.viaQUIC {
			// Penalise the address family actually used for the attempt (meta.dialAddr),
			// not necessarily the caller's stable addr hint.
			failAddr := meta.dialAddr
			if failAddr == nil {
				failAddr = peer
			}
			n.recordFailure(id, failAddr)
		}
		return nil, nil, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.recordSuccess(peerNID, successDialAddr(peer, meta), time.Since(t0))
	br := dec.Body.(*protocol.BodyFindValueResp)
	n.notifyObserved(peerNID, br.ObservedAddr)
	var out []protocol.SignedRecord
	if len(br.Records) > 0 {
		out = append(out, br.Records...)
	} else if br.Record != nil {
		out = append(out, *br.Record)
	}
	return out, br.Nodes, nil
}

// FindValue queries peer for the best endpoint record at key NodeID (legacy helper).
func (n *Node) FindValue(ctx context.Context, peer net.Addr, key a2al.NodeID) (*protocol.SignedRecord, error) {
	recs, _, err := n.FindValueWithNodes(ctx, peer, key, 0, false)
	if err != nil {
		return nil, err
	}
	var best *protocol.SignedRecord
	now := time.Now()
	for i := range recs {
		r := recs[i]
		if r.RecType != protocol.RecTypeEndpoint {
			continue
		}
		if protocol.VerifySignedRecord(r, now) != nil {
			continue
		}
		if best == nil || protocol.RecordIsNewer(r, *best) {
			x := r
			best = &x
		}
	}
	return best, nil
}

// AddContact pins a peer's dial address and seeds the routing table.
// Treated as a trusted (user-configured) contact: VerifiedAt is set to now.
func (n *Node) AddContact(addr net.Addr, ni protocol.NodeInfo) {
	var peerID a2al.NodeID
	copy(peerID[:], ni.NodeID)
	n.BindPeerAddr(peerID, addr)
	n.tabAdd(ni, routing.EntryMeta{VerifiedAt: time.Now()}, addr)
}

// LocalAddr returns the underlying transport address.
func (n *Node) LocalAddr() net.Addr { return n.tr.LocalAddr() }

// Address returns the agent address.
func (n *Node) Address() a2al.Address { return n.addr }

// NodeID returns the DHT key for this node.
func (n *Node) NodeID() a2al.NodeID { return n.nid }

// BootstrapCandidateAddrs returns up to max UDP addresses for cold-start bootstrap
// (routing table + remembered peer addrs). Best-effort for persisting peers.cache.
//
// Candidates are sorted by observed health: Good → Unknown → Bad.  The max cap
// therefore naturally favours peers we have successfully communicated with before,
// so that the next cold-start spends its bootstrap window on the most promising
// contacts rather than on known-dead nodes.
func (n *Node) BootstrapCandidateAddrs(max int) []net.Addr {
	if max <= 0 {
		return nil
	}
	n.tabMu.RLock()
	peers := n.table.AllPeers()
	n.tabMu.RUnlock()

	type candidate struct {
		addr   *net.UDPAddr
		health PeerHealthState
	}
	var candidates []candidate
	seen := make(map[string]struct{})

	for _, ni := range peers {
		if len(ni.NodeID) != len(n.nid) {
			continue
		}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}
		var udp *net.UDPAddr
		udp = n.bootstrapDialAddr(id, ni)
		if udp == nil {
			continue
		}
		k := udp.String()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		candidates = append(candidates, candidate{addr: udp, health: n.PeerHealthOf(id)})
	}

	// Sort Good first, Unknown second, Bad last so the max cap retains the
	// healthiest peers when the routing table is larger than max.
	healthPriority := func(h PeerHealthState) int {
		switch h {
		case PeerHealthGood:
			return 0
		case PeerHealthUnknown:
			return 1
		default: // PeerHealthBad
			return 2
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return healthPriority(candidates[i].health) < healthPriority(candidates[j].health)
	})

	out := make([]net.Addr, 0, min(len(candidates), max))
	for _, c := range candidates {
		if len(out) >= max {
			break
		}
		out = append(out, c.addr)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SetMaxStoreKeys updates the maximum number of distinct keys in the local store.
func (n *Node) SetMaxStoreKeys(max int) { n.store.SetMaxKeys(max) }

// StoreRxCount returns the cumulative number of STORE RPCs accepted by this node.
func (n *Node) StoreRxCount() uint64 { return n.statsStoreRx.Load() }

// FindValueServedCount returns the cumulative number of FIND_VALUE RPCs
// answered with at least one record by this node.
func (n *Node) FindValueServedCount() uint64 { return n.statsFindValueServed.Load() }

// SetPassiveRouting controls whether this node suppresses proactive FindNode
// queries. When true (passive mode), the node fills its routing table naturally
// through incoming traffic and skips active bucket-refill and topology scans.
func (n *Node) SetPassiveRouting(passive bool) { n.passiveRouting.Store(passive) }

// SelfExtIP returns the node's current public IP as seen by STUN/HTTP probe,
// or nil if not yet known.
func (n *Node) SelfExtIP() net.IP {
	n.selfExtMu.RLock()
	defer n.selfExtMu.RUnlock()
	return n.selfExtIP
}

// LocalStoreGet returns verified non-expired records at the given DHT key,
// with optional RecType filter (0 = all types).
func (n *Node) LocalStoreGet(key a2al.NodeID, recType uint8) []protocol.SignedRecord {
	return n.store.GetAll(key, recType, time.Now())
}

// LocalStoreGetByAddress returns verified non-expired records where sr.Address
// matches addr, with optional RecType filter (0 = all types). Scans all store
// buckets; intended for low-frequency paths such as the QUIC control exchange.
func (n *Node) LocalStoreGetByAddress(addr a2al.Address, recType uint8) []protocol.SignedRecord {
	return n.store.GetAllByAddress(addr, recType, time.Now())
}

// LocalStoreInvalidate removes locally-cached records for key and recType (0 = all
// types).  Used internally by the host layer to clear stale endpoint records when a
// connection attempt fails, so the next Resolve fetches fresh data from the network.
func (n *Node) LocalStoreInvalidate(key a2al.NodeID, recType uint8) {
	n.store.Invalidate(key, recType)
}

// epPrefetchNegEntry is the value stored in epPrefetchNeg.
type epPrefetchNegEntry struct {
	retryAt   time.Time
	failCount int
}

// clearEpPrefetchNeg removes the negative-cache entry for nodeID if present.
// Called whenever an endpoint record for nodeID is written to the local store,
// so that nodes suppressed by a prior transient lookup failure are unblocked.
func (n *Node) clearEpPrefetchNeg(nodeID a2al.NodeID) {
	key := nodeIDKey(nodeID)
	n.epPrefetchNegMu.Lock()
	delete(n.epPrefetchNeg, key)
	n.epPrefetchNegMu.Unlock()
}

// LocalStorePut writes rec into the local store without triggering replication.
// Use this to seed records received via an out-of-band channel (e.g. QUIC
// control plane AgentInfo push) so that subsequent AggregateRecords queries
// return the fresh data immediately.
//
// If rec is an endpoint record, any negative-cache entry for the same nodeID
// is cleared so that the replication gap-fill NAT track can use the new signal
// URL immediately rather than waiting for the suppression window to expire.
func (n *Node) LocalStorePut(storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if err := n.store.Put(storeKey, rec, time.Now()); err != nil {
		return err
	}
	if rec.RecType == protocol.RecTypeEndpoint {
		n.clearEpPrefetchNeg(storeKey)
	}
	return nil
}

// Close stops the node, closes the transport, and waits for the receive loop to exit.
func (n *Node) Close() error {
	n.cancel()
	err := n.tr.Close()
	n.wg.Wait()
	return err
}

// HandleReadRequest processes a raw signed DHT request received over a non-UDP
// channel (e.g. the signaling WebSocket) and returns the signed response bytes.
// Only read-only operations (PING, FIND_NODE, FIND_VALUE) are served; STORE and
// any other write operations are rejected by returning nil.
func (n *Node) HandleReadRequest(raw []byte) []byte {
	dec, err := protocol.VerifyAndDecode(raw)
	if err != nil {
		return nil
	}
	switch dec.Header.MsgType {
	case protocol.MsgPing:
		return n.buildSignedReply(dec, protocol.MsgPong, &protocol.BodyPong{
			Address: n.addr[:],
		})
	case protocol.MsgFindNode:
		target := dec.Body.(*protocol.BodyFindNode).Target
		var tid a2al.NodeID
		copy(tid[:], target)
		resp := &protocol.BodyFindNodeResp{
			Nodes: n.tabNearestHealthy(tid, routing.K),
		}
		// Trim to wire-size limit (same guard as onFindNode).
		for len(resp.Nodes) > 1 {
			sz, e := protocol.FindNodeResponseWireSize(resp)
			if e != nil || sz <= maxResponsePayload {
				break
			}
			resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
		}
		return n.buildSignedReply(dec, protocol.MsgFindNodeResp, resp)
	case protocol.MsgFindValue:
		body := dec.Body.(*protocol.BodyFindValue)
		var tid a2al.NodeID
		copy(tid[:], body.Target)
		now := time.Now()
		records := n.store.GetAll(tid, body.RecType, now)
		best := n.store.Get(tid, now)
		resp := &protocol.BodyFindValueResp{
			Nodes:   n.tabNearestHealthy(tid, routing.K),
			Records: records,
		}
		if best != nil && len(records) == 0 && (body.RecType == 0 || best.RecType == body.RecType) {
			r := *best
			resp.Record = &r
		}
		return n.buildSignedReply(dec, protocol.MsgFindValueResp, resp)
	default:
		return nil
	}
}

// BuildFindNodeRequest creates a signed FIND_NODE request targeting the given
// NodeID, suitable for sending via the signaling WebSocket DHT proxy.
func (n *Node) BuildFindNodeRequest(target a2al.NodeID) ([]byte, error) {
	var txID [16]byte
	if _, err := crand.Read(txID[:]); err != nil {
		return nil, err
	}
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: protocol.MsgFindNode,
		TxID:    txID[:],
	}
	return protocol.MarshalSignedMessageKeyStore(hdr, &protocol.BodyFindNode{Target: target[:]}, n.ks, n.addr)
}

// BuildFindValueRequest creates a signed FIND_VALUE request for the given key
// and record type, suitable for sending via the signaling WebSocket DHT proxy.
// recType 0 requests all record types.
func (n *Node) BuildFindValueRequest(target a2al.NodeID, recType uint8) ([]byte, error) {
	var txID [16]byte
	if _, err := crand.Read(txID[:]); err != nil {
		return nil, err
	}
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: protocol.MsgFindValue,
		TxID:    txID[:],
	}
	return protocol.MarshalSignedMessageKeyStore(hdr,
		&protocol.BodyFindValue{Target: target[:], RecType: recType},
		n.ks, n.addr)
}

// SeedRecord writes a pre-validated SignedRecord directly into the local store
// without triggering replication. For bootstrap seeding only: used when a record
// is obtained out-of-band (e.g. via the signaling WebSocket DHT proxy) and needs
// to be available locally before the DHT layer is operational.
func (n *Node) SeedRecord(rec protocol.SignedRecord) error {
	return n.store.Put(a2al.NodeID{}, rec, time.Now())
}

// buildSignedReply signs and serialises a DHT response body, reusing the
// request's TxID. Returns nil on marshalling error.
func (n *Node) buildSignedReply(req *protocol.DecodedMessage, msgType uint8, body any) []byte {
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: msgType,
		TxID:    append([]byte(nil), req.Header.TxID...),
	}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
	if err != nil {
		n.log.Debug("dht: buildSignedReply failed", "msg_type", msgType, "err", err)
		return nil
	}
	return raw
}

