// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"net"
	"testing"
	"time"

	ice "github.com/pion/ice/v3"

	"github.com/a2al/a2al/signaling"
)

func TestHintToRemoteCandidate_PeerReflexive(t *testing.T) {
	h := iceHint{
		addr:     net.UDPAddr{IP: net.ParseIP("2408:8206:482e:5660::13c"), Port: 59807},
		candType: ice.CandidateTypePeerReflexive,
	}
	cand, err := hintToRemoteCandidate(h)
	if err != nil {
		t.Fatal(err)
	}
	if cand.Type() != ice.CandidateTypePeerReflexive {
		t.Fatalf("type = %v, want PeerReflexive", cand.Type())
	}
	if cand.Address() != "2408:8206:482e:5660::13c" || cand.Port() != 59807 {
		t.Fatalf("addr = %s:%d", cand.Address(), cand.Port())
	}
}

// deferFastFail mirrors shouldDeferICEFastFail's decision tree so the
// composed logic can be exercised with hand-built stats; shouldDeferICEFastFail
// itself takes a live *ice.Agent and cannot be constructed without a running
// ICE session (see TestICESessionHostOnlyLoopback for that level of test).
func deferFastFail(stats []ice.CandidatePairStats, byID map[string]ice.CandidateStats, elapsed time.Duration, remoteGatherDone bool) bool {
	if elapsed > eocFallbackGrace {
		return false
	}
	if !v4PairsExhausted(stats, byID) {
		return false
	}
	if hasNonFailedV6Pair(stats, byID) {
		return true
	}
	if hasUnpairedIPv6HostCandidate(stats, byID) {
		return true
	}
	return !remoteGatherDone
}

func TestShouldDeferICEFastFail(t *testing.T) {
	v4Only := map[string]ice.CandidateStats{
		"loc4": {ID: "loc4", IP: "203.0.113.1", Port: 5000, CandidateType: ice.CandidateTypeHost},
		"rem4": {ID: "rem4", IP: "198.51.100.2", Port: 4121, CandidateType: ice.CandidateTypeServerReflexive},
	}
	dualStack := map[string]ice.CandidateStats{
		"loc4": {ID: "loc4", IP: "203.0.113.1", Port: 5000, CandidateType: ice.CandidateTypeHost},
		"rem4": {ID: "rem4", IP: "198.51.100.2", Port: 4121, CandidateType: ice.CandidateTypeServerReflexive},
		"loc6": {ID: "loc6", IP: "2408::1", Port: 5001, CandidateType: ice.CandidateTypeHost},
		"rem6": {ID: "rem6", IP: "2408::2", Port: 63595, CandidateType: ice.CandidateTypeHost},
	}

	tests := []struct {
		name             string
		stats            []ice.CandidatePairStats
		byID             map[string]ice.CandidateStats
		elapsed          time.Duration
		remoteGatherDone bool
		want             bool
	}{
		{
			name: "v4-only all failed remote still gathering defers within grace",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
			},
			byID:             v4Only,
			elapsed:          time.Second,
			remoteGatherDone: false,
			want:             true,
		},
		{
			name: "v4-only all failed remote still gathering past grace does not defer",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
			},
			byID:             v4Only,
			elapsed:          eocFallbackGrace + time.Second,
			remoteGatherDone: false,
			want:             false,
		},
		{
			name: "v4-only all failed remote done does not defer",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
			},
			byID:             v4Only,
			remoteGatherDone: true,
			want:             false,
		},
		{
			name: "v4 failed v6 pair still waiting defers",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
				{LocalCandidateID: "loc6", RemoteCandidateID: "rem6", State: ice.CandidatePairStateWaiting},
			},
			byID:             dualStack,
			remoteGatherDone: true,
			want:             true,
		},
		{
			name: "v4 and v6 pairs all failed remote done does not defer",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
				{LocalCandidateID: "loc6", RemoteCandidateID: "rem6", State: ice.CandidatePairStateFailed},
			},
			byID:             dualStack,
			remoteGatherDone: true,
			want:             false,
		},
		{
			name: "v4 failed no v6 pair yet but v6 host candidate seen defers despite remote done",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
			},
			byID:             dualStack,
			remoteGatherDone: true,
			want:             true,
		},
		{
			name: "v4 not yet exhausted does not defer",
			stats: []ice.CandidatePairStats{
				{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateWaiting},
			},
			byID: v4Only,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deferFastFail(tc.stats, tc.byID, tc.elapsed, tc.remoteGatherDone)
			if got != tc.want {
				t.Fatalf("defer = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHasUnpairedIPv6HostCandidate(t *testing.T) {
	v4Only := map[string]ice.CandidateStats{
		"loc4": {ID: "loc4", IP: "203.0.113.1", CandidateType: ice.CandidateTypeHost},
	}
	if hasUnpairedIPv6HostCandidate(nil, v4Only) {
		t.Fatal("expected false for v4-only candidates")
	}

	withV6Host := map[string]ice.CandidateStats{
		"loc4": {ID: "loc4", IP: "203.0.113.1", CandidateType: ice.CandidateTypeHost},
		"rem6": {ID: "rem6", IP: "2408::2", CandidateType: ice.CandidateTypeHost},
	}
	if !hasUnpairedIPv6HostCandidate(nil, withV6Host) {
		t.Fatal("expected true when a v6 host candidate has not formed any pair yet")
	}

	v6SrflxOnly := map[string]ice.CandidateStats{
		"rem6": {ID: "rem6", IP: "2408::2", CandidateType: ice.CandidateTypeServerReflexive},
	}
	if hasUnpairedIPv6HostCandidate(nil, v6SrflxOnly) {
		t.Fatal("expected false when the only v6 candidate is not a host type")
	}

	// A v6 host candidate whose only pair already failed has already had its
	// chance and should no longer be treated as a reason to keep waiting.
	failedPair := []ice.CandidatePairStats{
		{LocalCandidateID: "loc4", RemoteCandidateID: "rem6", State: ice.CandidatePairStateFailed},
	}
	if hasUnpairedIPv6HostCandidate(failedPair, withV6Host) {
		t.Fatal("expected false once the v6 host candidate's pair has failed")
	}
}

func TestV4PairsExhausted(t *testing.T) {
	byID := map[string]ice.CandidateStats{
		"loc4": {ID: "loc4", IP: "203.0.113.1", Port: 1},
		"rem4": {ID: "rem4", IP: "198.51.100.2", Port: 2},
		"loc6": {ID: "loc6", IP: "2408::1", Port: 3},
		"rem6": {ID: "rem6", IP: "2408::2", Port: 4},
	}
	stats := []ice.CandidatePairStats{
		{LocalCandidateID: "loc4", RemoteCandidateID: "rem4", State: ice.CandidatePairStateFailed},
		{LocalCandidateID: "loc6", RemoteCandidateID: "rem6", State: ice.CandidatePairStateWaiting},
	}
	if !v4PairsExhausted(stats, byID) {
		t.Fatal("expected v4 pairs exhausted")
	}
	if v4PairsExhausted(nil, byID) {
		t.Fatal("expected false for empty stats")
	}
}

func TestICESessionHostOnlyLoopback(t *testing.T) {
	relay, err := signaling.StartRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	room := signaling.RoomID("aidaaaaaaaaaaaaaaaaaaaa", "aidbbbbbbbbbbbbbbbbbbbb")
	wsURL, err := signaling.AppendRoomToICEURL(relay.BaseURL(), room)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type res struct {
		s *iceSession
		e error
	}
	ctrlCh := make(chan res, 1)
	othCh := make(chan res, 1)

	v4Only := []ice.NetworkType{ice.NetworkTypeUDP4}
	go func() {
		s, e := runICESession(ctx, wsURL, nil, true, true, false, v4Only, nil)
		ctrlCh <- res{s, e}
	}()
	go func() {
		s, e := runICESession(ctx, wsURL, nil, false, true, false, v4Only, nil)
		othCh <- res{s, e}
	}()

	a := <-ctrlCh
	b := <-othCh
	if a.e != nil {
		t.Fatal("controlling:", a.e)
	}
	if b.e != nil {
		t.Fatal("controlled:", b.e)
	}
	defer a.s.Close()
	defer b.s.Close()

	payload := []byte("a2al-ice-ping")
	if _, err := a.s.iceConn.Write(payload); err != nil {
		t.Fatal("write:", err)
	}
	buf := make([]byte, 256)
	n, err := b.s.iceConn.Read(buf)
	if err != nil {
		t.Fatal("read:", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("got %q want %q", buf[:n], payload)
	}
}
