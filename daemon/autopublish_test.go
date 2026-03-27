// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/internal/registry"
)

func TestAgentAliveForRepublish_noServiceTCP_requiresHeartbeat(t *testing.T) {
	aid, err := a2al.ParseAddress(strings.ToLower("A0" + strings.Repeat("cd", 20)))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		heartbeatAt: make(map[a2al.Address]time.Time),
	}
	e := &registry.Entry{AID: aid, ServiceTCP: ""}
	if d.agentAliveForRepublish(e) {
		t.Fatal("empty service_tcp and no heartbeat: want false")
	}
	d.heartbeatAt[aid] = time.Now()
	if !d.agentAliveForRepublish(e) {
		t.Fatal("empty service_tcp with fresh heartbeat: want true")
	}
}

func TestAgentAliveForRepublish_staleHeartbeat(t *testing.T) {
	aid, err := a2al.ParseAddress(strings.ToLower("A0" + strings.Repeat("ab", 20)))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		heartbeatAt: make(map[a2al.Address]time.Time),
	}
	e := &registry.Entry{AID: aid, ServiceTCP: ""}
	d.heartbeatAt[aid] = time.Now().Add(-2 * heartbeatTTL)
	if d.agentAliveForRepublish(e) {
		t.Fatal("stale heartbeat: want false")
	}
}
