// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	crand "crypto/rand"
	"errors"
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

	pendMu sync.Mutex
	wait   map[string]*waitEntry

	peerMu sync.Mutex
	peers  map[string]net.Addr

	recvOnce sync.Once
	wg       sync.WaitGroup

	tabMu sync.RWMutex // routing.Table (Add / NearestN)

	onObservedAddr func(reporter a2al.NodeID, wire []byte)
	auth           RecordAuthFunc // nil → no check

	statsRx  atomic.Uint64
	statsTx  atomic.Uint64
	statsRPC atomic.Uint64 // outbound request/response pairs (sendAndWait success)
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
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		tr:     cfg.Transport,
		ks:     cfg.Keystore,
		addr:   addr,
		nid:    nid,
		store:  NewStore(cfg.RecordAuth, cfg.MaxStoreKeys),
		ctx:    ctx,
		cancel: cancel,
		wait:           make(map[string]*waitEntry),
		peers:          make(map[string]net.Addr),
		onObservedAddr: cfg.OnObservedAddr,
		auth:           cfg.RecordAuth,
	}
	n.table = routing.NewTable(nid, nil)
	return n, nil
}

// Start begins the inbound packet loop.
func (n *Node) Start() {
	n.recvOnce.Do(func() {
		n.wg.Add(1)
		go n.recvLoop()
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
	n.peerMu.Lock()
	id := a2al.NodeIDFromAddress(dec.SenderAddr)
	n.peers[nodeIDKey(id)] = from
	n.peerMu.Unlock()
	n.tabAdd(nodeInfoFromMessage(dec, from))
}

func (n *Node) tabAdd(ni protocol.NodeInfo) {
	var nid a2al.NodeID
	if len(ni.NodeID) != len(nid) {
		return
	}
	copy(nid[:], ni.NodeID)

	n.tabMu.Lock()
	if n.table.Contains(nid) {
		n.table.Add(ni)
		n.tabMu.Unlock()
		return
	}
	if n.table.PeerBucketLen(nid) < routing.K {
		n.table.Add(ni)
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
	// Add may return false if a concurrent tabAdd already refilled this bucket
	// between the lock release above and re-acquisition here (TOCTOU: both
	// goroutines raced on the same oldest entry, one already evicted it and
	// filled the slot). Dropping ni is correct per Kademlia "prefer known nodes"
	// semantics; the node will be re-discovered via future lookups.
	_ = n.table.Add(ni)
	n.tabMu.Unlock()
}

func (n *Node) tabNearest(target a2al.NodeID, k int) []protocol.NodeInfo {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.NearestN(target, k)
}

// absorbNodeInfo merges a contact into the routing table and, when IP:port looks usable, sets UDP dial address.
func (n *Node) absorbNodeInfo(ni protocol.NodeInfo) {
	n.tabAdd(ni)
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
	defer n.peerMu.Unlock()
	n.peers[nodeIDKey(id)] = addr
}

func (n *Node) reply(from net.Addr, req *protocol.DecodedMessage, msgType uint8, body any) {
	hdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: msgType,
		TxID:    append([]byte(nil), req.Header.TxID...),
	}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, n.ks, n.addr)
	if err != nil {
		return
	}
	if err := n.tr.Send(from, raw); err == nil {
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
	n.remember(from, dec)
	target := dec.Body.(*protocol.BodyFindNode).Target
	var tid a2al.NodeID
	copy(tid[:], target)
	resp := &protocol.BodyFindNodeResp{
		Nodes:        n.tabNearest(tid, routing.K),
		ObservedAddr: ObservedAddr(from),
	}
	n.reply(from, dec, protocol.MsgFindNodeResp, resp)
}

func (n *Node) onFindValue(from net.Addr, dec *protocol.DecodedMessage) {
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
	if best != nil {
		r := *best
		resp.Record = &r
	}
	const maxPayload = 1100
	for {
		sz, err := protocol.FindValueResponseWireSize(resp)
		if err != nil || sz <= maxPayload {
			break
		}
		if len(resp.Nodes) > 1 {
			resp.Nodes = resp.Nodes[:len(resp.Nodes)-1]
			continue
		}
		if len(resp.Records) > 1 {
			resp.Records = resp.Records[:len(resp.Records)-1]
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

func (n *Node) sendAndWait(ctx context.Context, to net.Addr, hdr protocol.Header, body any, expect uint8) (*protocol.DecodedMessage, error) {
	if len(hdr.TxID) != 20 {
		hdr.TxID = make([]byte, 20)
		if _, err := crand.Read(hdr.TxID); err != nil {
			return nil, err
		}
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
	select {
	case dec := <-ch:
		n.statsRPC.Add(1)
		return dec, nil
	case <-ctx.Done():
		n.unregisterWait(hdr.TxID)
		return nil, ctx.Err()
	case <-n.ctx.Done():
		n.unregisterWait(hdr.TxID)
		return nil, n.ctx.Err()
	}
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
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgPong)
	if err != nil {
		return nil, err
	}
	pong, ok := dec.Body.(*protocol.BodyPong)
	if !ok {
		return nil, errors.New("dht: expected PONG")
	}
	peerAddr := dec.SenderAddr
	peerNID := a2al.NodeIDFromAddress(peerAddr)
	ni := nodeInfoFromMessage(dec, peer)
	n.BindPeerAddr(peerNID, peer)
	n.tabAdd(ni)
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
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgStoreResp)
	if err != nil {
		return false, err
	}
	return dec.Body.(*protocol.BodyStoreResp).Stored, nil
}

// FindNode asks peer for closest nodes to target NodeID.
func (n *Node) FindNode(ctx context.Context, peer net.Addr, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindNode}
	body := &protocol.BodyFindNode{Target: target[:]}
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindNodeResp)
	if err != nil {
		return nil, err
	}
	br := dec.Body.(*protocol.BodyFindNodeResp)
	n.notifyObserved(a2al.NodeIDFromAddress(dec.SenderAddr), br.ObservedAddr)
	return br.Nodes, nil
}

// FindValueWithNodes queries peer. recType 0 requests all record types in the response.
func (n *Node) FindValueWithNodes(ctx context.Context, peer net.Addr, key a2al.NodeID, recType uint8) ([]protocol.SignedRecord, []protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindValue}
	body := &protocol.BodyFindValue{Target: key[:], RecType: recType}
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindValueResp)
	if err != nil {
		return nil, nil, err
	}
	br := dec.Body.(*protocol.BodyFindValueResp)
	n.notifyObserved(a2al.NodeIDFromAddress(dec.SenderAddr), br.ObservedAddr)
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
	n.tabAdd(ni)
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
