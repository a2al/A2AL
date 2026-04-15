// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	crand "crypto/rand"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
	"github.com/a2al/a2al/transport"
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

type peerHealthEntry struct {
	lastSuccess time.Time
	lastFailure time.Time
	failCount   int
	rtt         time.Duration // last successful RTT; reserved for future RTT-based sorting
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
	peers  map[string]net.Addr

	addrToID sync.Map // addr.String() → a2al.NodeID (reverse of peers map)

	recvOnce sync.Once
	wg       sync.WaitGroup

	tabMu sync.RWMutex // routing.Table (Add / NearestN)

	onObservedAddr func(reporter a2al.NodeID, wire []byte)
	auth           RecordAuthFunc // nil → no check

	selfExtMu sync.RWMutex
	selfExtIP net.IP // our own public IP (set by host after STUN/HTTP probe)

	statsRx  atomic.Uint64
	statsTx  atomic.Uint64
	statsRPC atomic.Uint64 // outbound request/response pairs (sendAndWait success)

	decodeErrNext atomic.Int64 // unix-nano: next time a decode-error WARN may fire

	// seenPeers tracks unique NodeIDs contacted during this process lifetime.
	// key: [32]byte (a2al.NodeID), value: time.Time (first contact).
	// Used by /debug/stats to compute reach_1h/24h/7d.
	seenPeers     sync.Map
	seenPeersPath string // non-empty → persist to disk

	healthMu sync.RWMutex
	health   map[string]*peerHealthEntry // key: nodeIDKey(id)

	repMu         sync.RWMutex
	repSets       map[repKey]*repSet    // (storeKey, publisher) → replication tracking
	replCh        chan replTask         // 过程一 → 过程二: replication work items
	renewInFlight map[repKey]struct{}   // keys with a renewBackground goroutine running
}

type waitEntry struct {
	want uint8
	ch   chan *protocol.DecodedMessage
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
		wait:           make(map[string]*waitEntry),
		peers:          make(map[string]net.Addr),
		health:         make(map[string]*peerHealthEntry),
		repSets:        make(map[repKey]*repSet),
		replCh:         make(chan replTask, replChBuf),
		renewInFlight:  make(map[repKey]struct{}),
		onObservedAddr: cfg.OnObservedAddr,
		auth:           cfg.RecordAuth,
	}
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
		case protocol.MsgPong, protocol.MsgFindValueResp, protocol.MsgFindNodeResp, protocol.MsgStoreResp:
			continue
		case protocol.MsgPing:
			n.onPing(from, dec)
		case protocol.MsgFindNode:
			n.onFindNode(from, dec)
		case protocol.MsgFindValue:
			n.onFindValue(from, dec)
		case protocol.MsgStore:
			n.onStore(from, dec)
		default:
		}
	}
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
	a, ok := n.peers[nodeIDKey(id)]
	return a, ok
}

func (n *Node) remember(from net.Addr, dec *protocol.DecodedMessage) {
	id := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.peerMu.Lock()
	n.peers[nodeIDKey(id)] = from
	n.peerMu.Unlock()
	n.addrToID.Store(from.String(), id)
	n.tabAdd(nodeInfoFromMessage(dec, from), true)
}

// tabAdd inserts or refreshes ni in the routing table.  trusted must be true
// when ni originates from direct communication with the peer (observed UDP
// source address), so the stored IP:Port can be updated to the latest value.
// Pass false for NodeInfos received indirectly via FindNode responses.
func (n *Node) tabAdd(ni protocol.NodeInfo, trusted bool) {
	var nid a2al.NodeID
	if len(ni.NodeID) != len(nid) {
		return
	}
	copy(nid[:], ni.NodeID)
	n.seenPeers.LoadOrStore(nid, time.Now())

	n.tabMu.Lock()
	if n.table.Contains(nid) {
		n.table.Add(ni, trusted)
		n.tabMu.Unlock()
		return
	}
	if n.table.PeerBucketLen(nid) < routing.K {
		n.table.Add(ni, trusted)
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
	n.table.Add(ni, trusted)
	n.tabMu.Unlock()
}

func (n *Node) tabNearest(target a2al.NodeID, k int) []protocol.NodeInfo {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.NearestN(target, k)
}

// lookupPeerID returns the NodeID associated with addr, if known.
func (n *Node) lookupPeerID(addr net.Addr) (a2al.NodeID, bool) {
	v, ok := n.addrToID.Load(addr.String())
	if !ok {
		return a2al.NodeID{}, false
	}
	return v.(a2al.NodeID), true
}

// recordSuccess marks the peer as healthy (failCount reset to 0, RTT updated).
func (n *Node) recordSuccess(id a2al.NodeID, rtt time.Duration) {
	key := nodeIDKey(id)
	n.healthMu.Lock()
	e := n.health[key]
	if e == nil {
		e = &peerHealthEntry{}
		n.health[key] = e
	}
	e.lastSuccess = time.Now()
	e.failCount = 0
	if rtt > 0 {
		e.rtt = rtt
	}
	n.healthMu.Unlock()
}

// recordFailure increments the peer's consecutive-failure counter.
func (n *Node) recordFailure(id a2al.NodeID) {
	key := nodeIDKey(id)
	n.healthMu.Lock()
	e := n.health[key]
	if e == nil {
		e = &peerHealthEntry{}
		n.health[key] = e
	}
	e.lastFailure = time.Now()
	e.failCount++
	n.healthMu.Unlock()
}

// PeerHealthOf returns the observed health state for the given peer.
func (n *Node) PeerHealthOf(id a2al.NodeID) PeerHealthState {
	n.healthMu.RLock()
	e := n.health[nodeIDKey(id)]
	n.healthMu.RUnlock()
	if e == nil {
		return PeerHealthUnknown
	}
	if e.failCount >= badHealthThreshold {
		return PeerHealthBad
	}
	if !e.lastSuccess.IsZero() {
		return PeerHealthGood
	}
	return PeerHealthUnknown
}

// tabNearestHealthy returns up to k routing-table peers sorted first by
// health state (Good → Unknown → Bad) and then by XOR distance within each
// group.  This ensures StoreAt and query seeds prefer known-reachable nodes.
func (n *Node) tabNearestHealthy(target a2al.NodeID, k int) []protocol.NodeInfo {
	all := n.tabNearest(target, routing.K)
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

// reachCounts returns the number of unique peers seen within 1h, 24h, and 7d
// windows. Entries older than 7d are pruned during this scan (lazy cleanup).
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

// tabEstimatedNetworkSize returns the bucket-density estimate of network size.
func (n *Node) tabEstimatedNetworkSize() int {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.EstimatedNetworkSize()
}

// absorbNodeInfo merges a contact into the routing table and, when IP:port looks usable, sets UDP dial address.
func (n *Node) absorbNodeInfo(ni protocol.NodeInfo) {
	n.tabAdd(ni, false)
	if ni.Port == 0 || (len(ni.IP) != 4 && len(ni.IP) != 16) {
		return
	}
	var id a2al.NodeID
	if len(ni.NodeID) != len(id) {
		return
	}
	copy(id[:], ni.NodeID)
	udp := &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
	n.BindPeerAddr(id, udp)
}

// BindPeerAddr registers the transport dial address for a remote NodeID (e.g. MemTransport name lookup in tests).
func (n *Node) BindPeerAddr(id a2al.NodeID, addr net.Addr) {
	n.peerMu.Lock()
	n.peers[nodeIDKey(id)] = addr
	n.peerMu.Unlock()
	n.addrToID.Store(addr.String(), id)
}

// SetSelfExtIP records our own public IP (from STUN/HTTP probe). Used to detect
// NAT hairpin peers: nodes behind the same NAT share the same public IP and
// typically cannot reach each other via that IP (router hairpinning not supported).
func (n *Node) SetSelfExtIP(ip net.IP) {
	n.selfExtMu.Lock()
	n.selfExtIP = ip
	n.selfExtMu.Unlock()
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

func (n *Node) reply(from net.Addr, req *protocol.DecodedMessage, msgType uint8, body any) {
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: msgType,
		TxID:    append([]byte(nil), req.Header.TxID...),
	}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
	if err != nil {
		n.log.Warn("dht reply marshal failed", "msg_type", msgType, "to", from, "err", err)
		return
	}
	if err := n.tr.Send(from, raw); err != nil {
		n.log.Warn("dht reply send failed", "msg_type", msgType, "to", from, "size", len(raw), "err", err)
	} else {
		n.statsTx.Add(1)
	}
}

func (n *Node) onPing(from net.Addr, dec *protocol.DecodedMessage) {
	n.remember(from, dec)
	body := &protocol.BodyPong{
		Address:      n.addr[:],
		ObservedAddr: ObservedAddr(from),
	}
	n.reply(from, dec, protocol.MsgPong, body)
}

func (n *Node) onFindNode(from net.Addr, dec *protocol.DecodedMessage) {
	n.log.Debug("dht recv find_node", "from", from)
	n.remember(from, dec)
	target := dec.Body.(*protocol.BodyFindNode).Target
	var tid a2al.NodeID
	copy(tid[:], target)
	resp := &protocol.BodyFindNodeResp{
		Nodes:        n.tabNearest(tid, routing.K),
		ObservedAddr: ObservedAddr(from),
	}
	for len(resp.Nodes) > 1 {
		sz, err := protocol.FindNodeResponseWireSize(resp)
		if err != nil || sz <= maxResponsePayload {
			break
		}
		resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
	}
	n.reply(from, dec, protocol.MsgFindNodeResp, resp)
}

func (n *Node) onFindValue(from net.Addr, dec *protocol.DecodedMessage) {
	n.log.Debug("dht recv find_value", "from", from)
	n.remember(from, dec)
	body := dec.Body.(*protocol.BodyFindValue)
	var tid a2al.NodeID
	copy(tid[:], body.Target)
	now := time.Now()
	records := n.store.GetAll(tid, body.RecType, now)
	best := n.store.Get(tid, now)
	resp := &protocol.BodyFindValueResp{
		Nodes:        n.tabNearest(tid, routing.K),
		ObservedAddr: ObservedAddr(from),
		Records:      records,
	}
	// Only include the legacy Record field when it matches the requested type,
	// to avoid wasting packet space with unrelated record types (e.g. endpoint
	// records cluttering a mailbox query).
	if best != nil && (body.RecType == 0 || best.RecType == body.RecType) {
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
		break
	}
	n.reply(from, dec, protocol.MsgFindValueResp, resp)
}

func (n *Node) onStore(from net.Addr, dec *protocol.DecodedMessage) {
	n.remember(from, dec)
	body := dec.Body.(*protocol.BodyStore)
	var key a2al.NodeID
	if len(body.Key) == len(key) {
		copy(key[:], body.Key)
	}
	err := n.store.Put(key, body.Record, time.Now())
	ok := err == nil
	n.reply(from, dec, protocol.MsgStoreResp, &protocol.BodyStoreResp{Stored: ok})
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

func (n *Node) sendAndWait(ctx context.Context, to net.Addr, hdr protocol.Header, body any, expect uint8) (*protocol.DecodedMessage, error) {
	for attempt := 0; attempt < rpcMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Fresh TxID per attempt to avoid stale-response cross-matching.
		hdr.TxID = make([]byte, 20)
		if _, err := crand.Read(hdr.TxID); err != nil {
			return nil, err
		}
		ch := n.registerWait(hdr.TxID, expect)
		raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
		if err != nil {
			n.unregisterWait(hdr.TxID)
			return nil, err
		}
		if err := n.tr.Send(to, raw); err != nil {
			n.unregisterWait(hdr.TxID)
			return nil, err
		}
		n.statsTx.Add(1)

		aCtx, aCancel := context.WithTimeout(ctx, rpcAttemptTimeout)
		select {
		case dec := <-ch:
			aCancel()
			n.statsRPC.Add(1)
			return dec, nil
		case <-aCtx.Done():
			n.unregisterWait(hdr.TxID)
			aCancel()
			if n.ctx.Err() != nil {
				return nil, n.ctx.Err()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			n.log.Debug("dht rpc timeout, retrying", "to", to, "msg_type", hdr.MsgType, "attempt", attempt+1)
			// per-attempt timeout; retry
		case <-n.ctx.Done():
			n.unregisterWait(hdr.TxID)
			aCancel()
			return nil, n.ctx.Err()
		}
	}
	n.log.Warn("dht rpc failed after retries", "to", to, "msg_type", hdr.MsgType, "attempts", rpcMaxAttempts)
	return nil, context.DeadlineExceeded
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
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgPong)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok {
			n.recordFailure(id)
		}
		return nil, err
	}
	pong, ok := dec.Body.(*protocol.BodyPong)
	if !ok {
		return nil, errors.New("dht: expected PONG")
	}
	peerAddr := dec.SenderAddr
	peerNID := a2al.NodeIDFromAddress(peerAddr)
	n.recordSuccess(peerNID, time.Since(t0))
	ni := nodeInfoFromMessage(dec, peer)
	n.BindPeerAddr(peerNID, peer)
	n.tabAdd(ni, true)
	var obs []byte
	if len(pong.ObservedAddr) > 0 {
		obs = append([]byte(nil), pong.ObservedAddr...)
	}
	n.notifyObserved(peerNID, obs)
	return &PeerIdentity{Address: peerAddr, NodeID: peerNID, ObservedWire: obs}, nil
}

// StoreAt sends STORE to peer. storeKey zero omits BodyStore.Key (receiver derives key from rec.Address).
func (n *Node) StoreAt(ctx context.Context, peer net.Addr, storeKey a2al.NodeID, rec protocol.SignedRecord) (bool, error) {
	body := &protocol.BodyStore{Record: rec}
	if storeKey != (a2al.NodeID{}) {
		body.Key = storeKey[:]
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgStore}
	t0 := time.Now()
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgStoreResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok {
			n.recordFailure(id)
		}
		return false, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.recordSuccess(peerNID, time.Since(t0))
	return dec.Body.(*protocol.BodyStoreResp).Stored, nil
}

// FindNode asks peer for closest nodes to target NodeID.
func (n *Node) FindNode(ctx context.Context, peer net.Addr, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindNode}
	body := &protocol.BodyFindNode{Target: target[:]}
	t0 := time.Now()
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindNodeResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok {
			n.recordFailure(id)
		}
		return nil, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.recordSuccess(peerNID, time.Since(t0))
	br := dec.Body.(*protocol.BodyFindNodeResp)
	n.notifyObserved(peerNID, br.ObservedAddr)
	return br.Nodes, nil
}

// FindValueWithNodes queries peer. recType 0 requests all record types in the response.
func (n *Node) FindValueWithNodes(ctx context.Context, peer net.Addr, key a2al.NodeID, recType uint8) ([]protocol.SignedRecord, []protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindValue}
	body := &protocol.BodyFindValue{Target: key[:], RecType: recType}
	t0 := time.Now()
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindValueResp)
	if err != nil {
		if id, ok := n.lookupPeerID(peer); ok {
			n.recordFailure(id)
		}
		return nil, nil, err
	}
	peerNID := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.recordSuccess(peerNID, time.Since(t0))
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
	recs, _, err := n.FindValueWithNodes(ctx, peer, key, 0)
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
func (n *Node) AddContact(addr net.Addr, ni protocol.NodeInfo) {
	var peerID a2al.NodeID
	copy(peerID[:], ni.NodeID)
	n.peerMu.Lock()
	n.peers[nodeIDKey(peerID)] = addr
	n.peerMu.Unlock()
	n.tabAdd(ni, true)
}

// LocalAddr returns the underlying transport address.
func (n *Node) LocalAddr() net.Addr { return n.tr.LocalAddr() }

// Address returns the agent address.
func (n *Node) Address() a2al.Address { return n.addr }

// NodeID returns the DHT key for this node.
func (n *Node) NodeID() a2al.NodeID { return n.nid }

// BootstrapCandidateAddrs returns up to max UDP addresses for cold-start bootstrap
// (routing table + remembered peer addrs). Best-effort for persisting peers.cache.
func (n *Node) BootstrapCandidateAddrs(max int) []net.Addr {
	if max <= 0 {
		return nil
	}
	n.tabMu.RLock()
	peers := n.table.AllPeers()
	n.tabMu.RUnlock()
	var out []net.Addr
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
		n.peerMu.Lock()
		a, ok := n.peers[nodeIDKey(id)]
		n.peerMu.Unlock()
		if ok {
			if udp, ok := a.(*net.UDPAddr); ok && udp.Port != 0 {
				k := udp.String()
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					out = append(out, udp)
				}
			}
		} else if (len(ni.IP) == 4 || len(ni.IP) == 16) && ni.Port != 0 {
			udp := &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
			k := udp.String()
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				out = append(out, udp)
			}
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

// Close stops the node, closes the transport, and waits for the receive loop to exit.
func (n *Node) Close() error {
	n.cancel()
	err := n.tr.Close()
	n.wg.Wait()
	return err
}
