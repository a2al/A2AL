// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

// memKS is a minimal KeyStore for tests (single Ed25519 identity).
type memKS struct {
	priv ed25519.PrivateKey
	addr a2al.Address
}

func newMemKS(t *testing.T) *memKS {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &memKS{priv: priv, addr: addr}
}

func (m *memKS) Generate(crypto.KeyType) (crypto.PrivateKey, error) {
	return nil, errors.New("memKS: generate not supported")
}

func (m *memKS) Sign(addr a2al.Address, data []byte) ([]byte, error) {
	if addr != m.addr {
		return nil, errors.New("memKS: wrong address")
	}
	return ed25519.Sign(m.priv, data), nil
}

func (m *memKS) PublicKey(addr a2al.Address) ([]byte, error) {
	if addr != m.addr {
		return nil, errors.New("memKS: wrong address")
	}
	return m.priv.Public().(ed25519.PublicKey), nil
}

func (m *memKS) List() ([]a2al.Address, error) {
	return []a2al.Address{m.addr}, nil
}

func contactNI(addr a2al.Address) protocol.NodeInfo {
	nid := a2al.NodeIDFromAddress(addr)
	return protocol.NodeInfo{
		Address: append([]byte(nil), addr[:]...),
		NodeID:  append([]byte(nil), nid[:]...),
		IP:      net.IPv4(127, 0, 0, 1).To4(),
		Port:    0,
	}
}

func TestMemTransport_pingPongWire(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, err := netw.NewTransport("a")
	if err != nil {
		t.Fatal(err)
	}
	trB, err := netw.NewTransport("b")
	if err != nil {
		t.Fatal(err)
	}
	defer trA.Close()
	defer trB.Close()

	ksA, ksB := newMemKS(t), newMemKS(t)
	tx := make([]byte, 20)
	if _, err := rand.Read(tx); err != nil {
		t.Fatal(err)
	}
	hdr := protocol.Header{Version: protocol.ProtocolVersion, MsgType: protocol.MsgPing, TxID: tx}
	body := &protocol.BodyPing{Address: ksA.addr[:]}
	raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, ksA, ksA.addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := trA.Send(trB.LocalAddr(), raw); err != nil {
		t.Fatal(err)
	}

	pkt, from, err := trB.Receive()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := protocol.VerifyAndDecode(pkt)
	if err != nil {
		t.Fatalf("B verify PING: %v", err)
	}
	respHdr := protocol.Header{
		Version: protocol.ProtocolVersion,
		MsgType: protocol.MsgPong,
		TxID:    append([]byte(nil), dec.Header.TxID...),
	}
	respBody := &protocol.BodyPong{
		Address:      ksB.addr[:],
		ObservedAddr: ObservedAddr(from),
	}
	raw2, err := protocol.MarshalSignedMessageKeyStore(respHdr, respBody, ksB, ksB.addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := trB.Send(trA.LocalAddr(), raw2); err != nil {
		t.Fatal(err)
	}

	pkt2, _, err := trA.Receive()
	if err != nil {
		t.Fatal(err)
	}
	dec2, err := protocol.VerifyAndDecode(pkt2)
	if err != nil {
		t.Fatalf("A verify PONG: %v", err)
	}
	if string(dec2.Header.TxID) != string(tx) {
		t.Fatal("txid mismatch")
	}
}

func TestNode_pingPongMem(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, err := netw.NewTransport("a")
	if err != nil {
		t.Fatal(err)
	}
	trB, err := netw.NewTransport("b")
	if err != nil {
		t.Fatal(err)
	}
	defer trA.Close()
	defer trB.Close()

	ksA, ksB := newMemKS(t), newMemKS(t)
	nodeA, err := NewNode(Config{Transport: trA, Keystore: ksA})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := NewNode(Config{Transport: trB, Keystore: ksB})
	if err != nil {
		t.Fatal(err)
	}
	nodeA.Start()
	nodeB.Start()
	defer nodeA.Close()
	defer nodeB.Close()

	nodeA.AddContact(trB.LocalAddr(), contactNI(ksB.addr))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := nodeA.Ping(ctx, trB.LocalAddr()); err != nil {
		t.Fatal(err)
	}
}

func TestNode_storeAndFindValue(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("a")
	trB, _ := netw.NewTransport("b")
	defer trA.Close()
	defer trB.Close()

	ksA, ksB := newMemKS(t), newMemKS(t)
	nodeA, _ := NewNode(Config{Transport: trA, Keystore: ksA})
	nodeB, _ := NewNode(Config{Transport: trB, Keystore: ksB})
	nodeA.Start()
	nodeB.Start()
	defer nodeA.Close()
	defer nodeB.Close()

	nodeA.AddContact(trB.LocalAddr(), contactNI(ksB.addr))

	now := time.Now().Truncate(time.Second)
	rec, err := protocol.SignEndpointRecord(ksA.priv, ksA.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:4242"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := nodeA.StoreAt(ctx, trB.LocalAddr(), a2al.NodeID{}, rec)
	if err != nil || !ok {
		t.Fatalf("store %v %v", ok, err)
	}

	key := a2al.NodeIDFromAddress(ksA.addr)
	got, err := nodeA.FindValue(ctx, trB.LocalAddr(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || string(got.Payload) != string(rec.Payload) {
		t.Fatal("find value mismatch")
	}
}
