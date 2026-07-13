// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"testing"

	ice "github.com/pion/ice/v3"

	"github.com/a2al/a2al"
)

type fakeCandidate struct {
	ice.Candidate
	addr string
	port int
	typ  ice.CandidateType
}

func (f *fakeCandidate) Address() string      { return f.addr }
func (f *fakeCandidate) Port() int            { return f.port }
func (f *fakeCandidate) Type() ice.CandidateType { return f.typ }

// TestPeerICECache_ClearRemovesAllHints verifies that Clear wipes hints for
// every remote AID, not just one — a network-wide topology change (e.g. VPN
// disconnect) invalidates every cached srflx pair regardless of which peer
// it was recorded against.
func TestPeerICECache_ClearRemovesAllHints(t *testing.T) {
	var c peerICECache
	c.init()

	remoteA := a2al.Address{0x01}
	remoteB := a2al.Address{0x02}

	cand := &fakeCandidate{addr: "203.0.113.10", port: 4121, typ: ice.CandidateTypeServerReflexive}
	c.Record(remoteA, cand, nil)
	c.Record(remoteB, cand, nil)

	if len(c.Hints(remoteA)) == 0 || len(c.Hints(remoteB)) == 0 {
		t.Fatal("expected hints to be recorded for both peers before Clear")
	}

	c.Clear()

	if got := c.Hints(remoteA); len(got) != 0 {
		t.Fatalf("Hints(remoteA) after Clear = %v, want empty", got)
	}
	if got := c.Hints(remoteB); len(got) != 0 {
		t.Fatalf("Hints(remoteB) after Clear = %v, want empty", got)
	}
}

// TestPeerICECache_ClearThenRecordStillWorks verifies the cache remains
// usable after Clear — a subsequent successful ICE session must still be
// able to populate fresh hints (Clear must not leave the map nil in a way
// that breaks Record).
func TestPeerICECache_ClearThenRecordStillWorks(t *testing.T) {
	var c peerICECache
	c.init()
	c.Clear()

	remote := a2al.Address{0x03}
	cand := &fakeCandidate{addr: "203.0.113.20", port: 4121, typ: ice.CandidateTypeServerReflexive}
	c.Record(remote, cand, nil)

	hints := c.Hints(remote)
	if len(hints) != 1 {
		t.Fatalf("Hints after Record post-Clear = %d entries, want 1", len(hints))
	}
	want := net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 4121}
	if hints[0].addr.String() != want.String() {
		t.Fatalf("recorded hint addr = %v, want %v", hints[0].addr, want)
	}
}

func TestPeerICECache_RecordPeerReflexive(t *testing.T) {
	var c peerICECache
	c.init()

	remote := a2al.Address{0x04}
	cand := &fakeCandidate{
		addr: "2408:8206:482e:5660::13c",
		port: 59807,
		typ:  ice.CandidateTypePeerReflexive,
	}
	c.Record(remote, cand, nil)

	hints := c.Hints(remote)
	if len(hints) != 1 {
		t.Fatalf("Hints = %d entries, want 1", len(hints))
	}
	if hints[0].candType != ice.CandidateTypePeerReflexive {
		t.Fatalf("candType = %v, want PeerReflexive", hints[0].candType)
	}

	rebuilt, err := hintToRemoteCandidate(hints[0])
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Type() != ice.CandidateTypePeerReflexive {
		t.Fatalf("rebuilt type = %v, want PeerReflexive", rebuilt.Type())
	}
}
