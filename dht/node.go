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
		store:  NewStore(),
		ctx:    ctx,
		cancel: cancel,
		wait:           make(map[string]*waitEntry),
		peers:          make(map[string]net.Addr),
		onObservedAddr: cfg.OnObservedAddr,
	}
	n.table = routing.NewTable(nid, func(ni protocol.NodeInfo) bool {
		pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var peerID a2al.NodeID
		copy(peerID[:], ni.NodeID)
		a, ok := n.lookupPeer(peerID)
		if !ok {
			return false
		}
		return n.Ping(pctx, a) == nil
	})
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
	n.tabMu.Lock()
	defer n.tabMu.Unlock()
	n.table.Add(ni)
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
	target := dec.Body.(*protocol.BodyFindValue).Target
	var tid a2al.NodeID
	copy(tid[:], target)
	rec := n.store.Get(tid, time.Now())
	resp := &protocol.BodyFindValueResp{
		Nodes:        n.tabNearest(tid, routing.K),
		ObservedAddr: ObservedAddr(from),
	}
	if rec != nil {
		r := *rec
		resp.Record = &r
	}
	n.reply(from, dec, protocol.MsgFindValueResp, resp)
}

func (n *Node) onStore(from net.Addr, dec *protocol.DecodedMessage) {
	n.remember(from, dec)
	body := dec.Body.(*protocol.BodyStore)
	ok := n.store.Put(body.Record, time.Now()) == nil
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

// StoreAt sends STORE to peer and waits for STORE_RESP.
func (n *Node) StoreAt(ctx context.Context, peer net.Addr, rec protocol.SignedRecord) (bool, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgStore}
	body := &protocol.BodyStore{Record: rec}
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

// FindValueWithNodes queries peer; returns optional record and closest nodes from the response.
func (n *Node) FindValueWithNodes(ctx context.Context, peer net.Addr, key a2al.NodeID) (*protocol.SignedRecord, []protocol.NodeInfo, error) {
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgFindValue}
	body := &protocol.BodyFindValue{Target: key[:]}
	dec, err := n.sendAndWait(ctx, peer, hdr, body, protocol.MsgFindValueResp)
	if err != nil {
		return nil, nil, err
	}
	br := dec.Body.(*protocol.BodyFindValueResp)
	n.notifyObserved(a2al.NodeIDFromAddress(dec.SenderAddr), br.ObservedAddr)
	if br.Record == nil {
		return nil, br.Nodes, nil
	}
	r := *br.Record
	return &r, br.Nodes, nil
}

// FindValue queries peer for a record at key NodeID.
func (n *Node) FindValue(ctx context.Context, peer net.Addr, key a2al.NodeID) (*protocol.SignedRecord, error) {
	rec, _, err := n.FindValueWithNodes(ctx, peer, key)
	return rec, err
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

// Close stops the node, closes the transport, and waits for the receive loop to exit.
func (n *Node) Close() error {
	n.cancel()
	err := n.tr.Close()
	n.wg.Wait()
	return err
}
