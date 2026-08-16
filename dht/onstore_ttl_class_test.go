// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
)

type ttlClass int

const (
	ttlAuthoritative ttlClass = iota + 1
	ttlPathCache
)

const testSignedTTL uint32 = 3600

type recIdentity struct {
	priv ed25519.PrivateKey
	addr a2al.Address
	key  a2al.NodeID
}

func newRecIdentity(t *testing.T) recIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return recIdentity{priv: priv, addr: addr, key: a2al.NodeIDFromAddress(addr)}
}

func (id recIdentity) signEP(t *testing.T, endpoints []string, seq uint64, ts time.Time) protocol.SignedRecord {
	t.Helper()
	sr, err := protocol.SignEndpointRecord(id.priv, id.addr, protocol.EndpointPayload{
		Endpoints: endpoints,
		NatType:   protocol.NATRestricted,
	}, seq, uint64(ts.Unix()), testSignedTTL)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

func (id recIdentity) sign02(t *testing.T, seq uint64, ts time.Time) protocol.SignedRecord {
	t.Helper()
	sr, err := protocol.SignRecord(id.priv, id.addr, protocol.RecTypeAgentProfile, []byte{0xa0}, seq, uint64(ts.Unix()), testSignedTTL)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

func fireStore(n *Node, from net.Addr, sender a2al.Address, rec protocol.SignedRecord) {
	key := recordKeyForSigned(rec)
	n.onStore(from, inboundChannelUDP, &protocol.DecodedMessage{
		Header: protocol.Header{
			Version: protocol.ProtocolVersion,
			MsgType: protocol.MsgStore,
			TxID:    make([]byte, 20),
		},
		SenderAddr: sender,
		Body:       &protocol.BodyStore{Record: rec, Key: key[:]},
	})
}

func softDeadline(s *Store, key a2al.NodeID, recType uint8) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dl, ok := s.softExpiry[softExpiryKey(key, recType)]
	return dl, ok
}

func assertTTLClass(t *testing.T, s *Store, key a2al.NodeID, recType uint8, now time.Time, want ttlClass) {
	t.Helper()
	dl, has := softDeadline(s, key, recType)
	dead := s.GetAll(key, recType, now.Add(time.Duration(testSignedTTL)*time.Second+2*time.Second))
	switch want {
	case ttlAuthoritative:
		if has {
			t.Fatal("authoritative record has soft expiry — classified as path-cache")
		}
		if got := s.GetAll(key, recType, now.Add(pathCacheSoftTTL+time.Second)); len(got) == 0 {
			t.Fatal("authoritative record hidden inside signed TTL — treated as path-cache")
		}
		if len(dead) != 0 {
			t.Fatal("authoritative record survived signed TTL")
		}
	case ttlPathCache:
		if !has {
			t.Fatal("path-cache record missing soft expiry — classified as authoritative")
		}
		if got := s.GetAll(key, recType, dl.Add(-time.Nanosecond)); len(got) == 0 {
			t.Fatal("path-cache hidden before soft deadline")
		}
		if got := s.GetAll(key, recType, dl.Add(time.Nanosecond)); len(got) != 0 {
			t.Fatal("path-cache still visible after soft deadline")
		}
		if len(dead) != 0 {
			t.Fatal("path-cache survived signed TTL")
		}
	default:
		t.Fatalf("unknown ttl class %d", want)
	}
}

func TestOnStore_TTLClass(t *testing.T) {
	pubIP := net.IPv4(192, 0, 2, 1)
	pubFrom := &net.UDPAddr{IP: pubIP, Port: 4121}
	ep := []string{"quic://192.0.2.1:4121"}
	querierFrom := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 9}

	type step struct {
		name string
		run  func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass)
	}
	cases := []step{
		{
			name: "self-publish 0x01",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				id := newRecIdentity(t)
				fireStore(n, pubFrom, id.addr, id.signEP(t, ep, 1, time.Now()))
				return id.key, protocol.RecTypeEndpoint, ttlAuthoritative
			},
		},
		{
			name: "hosted 0x01 matching IP",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				agent := newRecIdentity(t)
				daemon := newRecIdentity(t)
				fireStore(n, pubFrom, daemon.addr, agent.signEP(t, ep, 1, time.Now()))
				return agent.key, protocol.RecTypeEndpoint, ttlAuthoritative
			},
		},
		{
			name: "hosted 0x02 with local 0x01 matching IP",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				agent := newRecIdentity(t)
				daemon := newRecIdentity(t)
				if err := n.LocalStorePut(agent.key, agent.signEP(t, ep, 1, time.Now())); err != nil {
					t.Fatal(err)
				}
				fireStore(n, pubFrom, daemon.addr, agent.sign02(t, 1, time.Now()))
				return agent.key, protocol.RecTypeAgentProfile, ttlAuthoritative
			},
		},
		{
			name: "hosted 0x02 without 0x01",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				agent := newRecIdentity(t)
				daemon := newRecIdentity(t)
				fireStore(n, pubFrom, daemon.addr, agent.sign02(t, 1, time.Now()))
				return agent.key, protocol.RecTypeAgentProfile, ttlPathCache
			},
		},
		{
			name: "hosted 0x02 with 0x01 but wrong IP",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				agent := newRecIdentity(t)
				daemon := newRecIdentity(t)
				if err := n.LocalStorePut(agent.key, agent.signEP(t, ep, 1, time.Now())); err != nil {
					t.Fatal(err)
				}
				fireStore(n, querierFrom, daemon.addr, agent.sign02(t, 1, time.Now()))
				return agent.key, protocol.RecTypeAgentProfile, ttlPathCache
			},
		},
		{
			name: "querier 0x01 into empty slot",
			run: func(t *testing.T, n *Node) (a2al.NodeID, uint8, ttlClass) {
				agent := newRecIdentity(t)
				querier := newRecIdentity(t)
				fireStore(n, querierFrom, querier.addr, agent.signEP(t, ep, 1, time.Now()))
				return agent.key, protocol.RecTypeEndpoint, ttlPathCache
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newHealthTestNode(t)
			key, recType, want := tc.run(t, n)
			assertTTLClass(t, n.store, key, recType, time.Now(), want)
		})
	}
}

func TestOnStore_PathCacheDoesNotDowngradeOccupied(t *testing.T) {
	n := newHealthTestNode(t)
	agent := newRecIdentity(t)
	querier := newRecIdentity(t)
	pubFrom := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4121}
	ep := []string{"quic://192.0.2.1:4121"}
	fireStore(n, pubFrom, agent.addr, agent.signEP(t, ep, 1, time.Now()))
	if storeHasSoftExpiry(n.store, agent.key, protocol.RecTypeEndpoint) {
		t.Fatal("self-publish armed soft expiry")
	}

	querierFrom := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 9}
	fireStore(n, querierFrom, querier.addr, agent.signEP(t, ep, 2, time.Now()))
	assertTTLClass(t, n.store, agent.key, protocol.RecTypeEndpoint, time.Now(), ttlAuthoritative)
	got := n.store.GetAll(agent.key, protocol.RecTypeEndpoint, time.Now())
	if len(got) != 1 || got[0].Seq != 2 {
		t.Fatal("higher-seq path-cache should replace content but not downgrade TTL class")
	}
}

func TestOnStore_AuthoritativeCoversSoftExpired(t *testing.T) {
	n := newHealthTestNode(t)
	agent := newRecIdentity(t)
	querier := newRecIdentity(t)
	pubFrom := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4121}
	querierFrom := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 9}
	ep := []string{"quic://192.0.2.1:4121"}
	now := time.Now()

	fireStore(n, querierFrom, querier.addr, agent.signEP(t, ep, 1, now))
	if !storeHasSoftExpiry(n.store, agent.key, protocol.RecTypeEndpoint) {
		t.Fatal("path-cache should arm soft expiry")
	}
	n.store.SetSoftExpiry(agent.key, protocol.RecTypeEndpoint, now.Add(-time.Second))
	if len(n.store.GetAll(agent.key, protocol.RecTypeEndpoint, time.Now())) != 0 {
		t.Fatal("expected GetAll empty after forced soft expiry")
	}

	fireStore(n, pubFrom, agent.addr, agent.signEP(t, ep, 2, time.Now()))
	assertTTLClass(t, n.store, agent.key, protocol.RecTypeEndpoint, time.Now(), ttlAuthoritative)
}

func TestOnStore_EvilTwin_HostedRenewAfterSoftExpiry(t *testing.T) {
	// Simulates the regression: hosted-agent authoritative record was
	// mis-armed with soft expiry; GetAll looks empty; next renew must
	// still classify as authoritative and clear the leftover deadline.
	n := newHealthTestNode(t)
	agent := newRecIdentity(t)
	daemon := newRecIdentity(t)
	pubFrom := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4121}
	ep := []string{"quic://192.0.2.1:4121"}

	fireStore(n, pubFrom, daemon.addr, agent.signEP(t, ep, 1, time.Now()))
	if storeHasSoftExpiry(n.store, agent.key, protocol.RecTypeEndpoint) {
		t.Fatal("hosted matching-IP store classified as path-cache")
	}
	n.store.SetSoftExpiry(agent.key, protocol.RecTypeEndpoint, time.Now().Add(-time.Second))
	if len(n.store.GetAll(agent.key, protocol.RecTypeEndpoint, time.Now())) != 0 {
		t.Fatal("expected GetAll empty")
	}

	fireStore(n, pubFrom, daemon.addr, agent.signEP(t, ep, 2, time.Now()))
	assertTTLClass(t, n.store, agent.key, protocol.RecTypeEndpoint, time.Now(), ttlAuthoritative)
}

func TestOnStore_PathCacheCannotReArmOccupied(t *testing.T) {
	n := newHealthTestNode(t)
	agent := newRecIdentity(t)
	querier := newRecIdentity(t)
	pubFrom := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4121}
	querierFrom := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 9}
	ep := []string{"quic://192.0.2.1:4121"}

	fireStore(n, pubFrom, agent.addr, agent.signEP(t, ep, 1, time.Now()))
	fireStore(n, querierFrom, querier.addr, agent.signEP(t, ep, 1, time.Now())) // same seq → alreadyHad
	assertTTLClass(t, n.store, agent.key, protocol.RecTypeEndpoint, time.Now(), ttlAuthoritative)
}
