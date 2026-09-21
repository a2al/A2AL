// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

func TestHookTable_independentApps(t *testing.T) {
	d := &Daemon{}
	var aid a2al.Address
	aid[0] = 1

	d.RegisterEnvelopeConsumer("app.a", func(a2al.Address, a2al.Address, string, []byte) (bool, EnvelopeResult) {
		return true, EnvelopeResult{Code: 1}
	})
	d.RegisterPending("app_a", func(a a2al.Address) int {
		if a == aid {
			return 1
		}
		return 0
	})
	d.RegisterEnvelopeConsumer("app.b", func(a2al.Address, a2al.Address, string, []byte) (bool, EnvelopeResult) {
		return true, EnvelopeResult{Code: 2}
	})
	d.RegisterPending("app_b", func(a a2al.Address) int {
		if a == aid {
			return 2
		}
		return 0
	})

	okA, resA := d.consumeEnvelope(aid, aid, "app.a", nil)
	okB, resB := d.consumeEnvelope(aid, aid, "app.b", nil)
	if !okA || resA.Code != 1 || !okB || resB.Code != 2 {
		t.Fatalf("consumers a=%v/%d b=%v/%d", okA, resA.Code, okB, resB.Code)
	}
	per, _ := d.pendingShape([]a2al.Address{aid})[aid.String()].(map[string]any)
	if per["app_a"] != 1 || per["app_b"] != 2 {
		t.Fatalf("pending %v", d.pendingShape([]a2al.Address{aid}))
	}

	d.RegisterEnvelopeConsumer("app.a", nil)
	d.RegisterPending("app_a", nil)
	okA, resA = d.consumeEnvelope(aid, aid, "app.a", nil)
	if okA || resA.Code != protocol.EnvelopeDenied {
		t.Fatalf("removed consumer still live: %v %d", okA, resA.Code)
	}
	okB, resB = d.consumeEnvelope(aid, aid, "app.b", nil)
	if !okB || resB.Code != 2 {
		t.Fatalf("other app wiped: %v %d", okB, resB.Code)
	}
	per, _ = d.pendingShape([]a2al.Address{aid})[aid.String()].(map[string]any)
	if _, has := per["app_a"]; has || per["app_b"] != 2 {
		t.Fatalf("after unregister %v", d.pendingShape([]a2al.Address{aid}))
	}
}

func TestHookTable_zeroDaemonReady(t *testing.T) {
	d := &Daemon{}
	d.RegisterEnvelopeConsumer("app.k", func(a2al.Address, a2al.Address, string, []byte) (bool, EnvelopeResult) {
		return true, EnvelopeResult{Code: 3}
	})
	d.RegisterPending("app_x", func(a2al.Address) int { return 4 })
	d.aclIP = newACLIPGate()
	d.tunnels = newTunnelRegistry()
	if !d.hasEnvelopeConsumers() {
		t.Fatal("envelope hook lost after later construction")
	}
	if d.clonePendingSources()["app_x"] == nil {
		t.Fatal("pending hook lost after later construction")
	}
}
