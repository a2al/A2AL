// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"testing"
	"time"
)

func TestTouchHeartbeat_safeUnderRegLock(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	done := make(chan struct{})
	go func() {
		d.regMu.Lock()
		d.touchHeartbeat(aid)
		d.regMu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("touchHeartbeat re-entered regMu")
	}
}

func TestExecAgentPatch_stalePublishDoesNotDeadlock(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	tcp := "127.0.0.1:1"
	done := make(chan error, 1)
	go func() {
		done <- d.execAgentPatch(aid.String(), patchAgentReq{ServiceTCP: &tcp})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("execAgentPatch deadlocked on regMu re-entry")
	}
	e := d.reg.Get(aid)
	if e == nil || e.ServiceTCP != tcp {
		t.Fatalf("service_tcp=%q", e.ServiceTCP)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("patch must record liveness")
	}
}

func TestExecTopicUnregister_stalePublishDoesNotDeadlock(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	done := make(chan error, 1)
	go func() {
		done <- d.execTopicUnregister(aid.String(), "demo.echo")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("execTopicUnregister deadlocked on regMu re-entry")
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("unregister must record liveness")
	}
}
