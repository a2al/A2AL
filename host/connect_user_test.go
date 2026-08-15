// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"testing"

	"github.com/a2al/a2al/protocol"
)

func TestEndpointDialFingerprint(t *testing.T) {
	a := &protocol.EndpointRecord{
		Endpoints: []string{"quic://1.1.1.1:1", "quic://2.2.2.2:2"},
		Signals:   []string{"wss://s.example/a", "wss://s.example/b"},
		Seq:       1,
	}
	b := &protocol.EndpointRecord{
		Endpoints: []string{"quic://2.2.2.2:2", "quic://1.1.1.1:1"},
		Signals:   []string{"wss://s.example/b", "wss://s.example/a"},
		Seq:       9,
	}
	if endpointDialFingerprint(a) != endpointDialFingerprint(b) {
		t.Fatal("same endpoints/signals must share fingerprint across seq")
	}

	c := &protocol.EndpointRecord{
		Endpoints: []string{"quic://3.3.3.3:3"},
		Signals:   a.Signals,
		Seq:       2,
	}
	if endpointDialFingerprint(a) == endpointDialFingerprint(c) {
		t.Fatal("endpoint change must change fingerprint")
	}

	legacy := &protocol.EndpointRecord{
		Endpoints: []string{"quic://1.1.1.1:1"},
		Signal:    "wss://s.example/a",
	}
	listed := &protocol.EndpointRecord{
		Endpoints: []string{"quic://1.1.1.1:1"},
		Signals:   []string{"wss://s.example/a"},
	}
	if endpointDialFingerprint(legacy) != endpointDialFingerprint(listed) {
		t.Fatal("legacy Signal must match Signals[0]")
	}
}
