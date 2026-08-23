// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"testing"
	"time"

	"github.com/a2al/a2al/internal/registry"
)

func TestACLIPGate_burstLocksWithoutFurtherEval(t *testing.T) {
	g := newACLIPGate()
	src := testUDP("10.2.0.1")
	for i := 0; i < aclIPShortMax; i++ {
		if g.locked(src) {
			t.Fatalf("locked on attempt %d", i)
		}
		g.noteFail(src)
	}
	if !g.locked(src) {
		t.Fatal("want lock after short-window burst")
	}
	// Another fail during lock must not be required; locked stays.
	g.noteFail(src)
	if !g.locked(src) {
		t.Fatal("lock should hold")
	}
}

func TestACLIPGate_successClears(t *testing.T) {
	g := newACLIPGate()
	src := testUDP("10.2.0.2")
	for i := 0; i < aclIPShortMax; i++ {
		g.noteFail(src)
	}
	g.noteOK(src)
	if g.locked(src) {
		t.Fatal("success must clear lock")
	}
	g.noteFail(src)
	if g.locked(src) {
		t.Fatal("cleared IP should get a fresh window")
	}
}

func TestACLIPGate_dripHitsLongWindow(t *testing.T) {
	g := newACLIPGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	src := testUDP("10.2.0.3")
	for i := 0; i < aclIPLongMax; i++ {
		now = now.Add(aclIPShortWindow + time.Second) // stay under short burst
		if g.locked(src) {
			t.Fatalf("locked early at %d", i)
		}
		g.noteFail(src)
	}
	if !g.locked(src) {
		t.Fatal("want lock after long-window cap")
	}
}

func TestACLIPGate_lockExpires(t *testing.T) {
	g := newACLIPGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	src := testUDP("10.2.0.4")
	for i := 0; i < aclIPShortMax; i++ {
		g.noteFail(src)
	}
	now = now.Add(aclIPLock + time.Second)
	if g.locked(src) {
		t.Fatal("lock should expire")
	}
}

func TestACLIPGate_ipsIndependent(t *testing.T) {
	g := newACLIPGate()
	a := testUDP("10.2.0.5")
	b := testUDP("10.2.0.6")
	for i := 0; i < aclIPShortMax; i++ {
		g.noteFail(a)
	}
	if g.locked(b) {
		t.Fatal("other IP must not lock")
	}
}

func TestDecideAccess_agentIPLockSkipsPassword(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	e := d.reg.Get(aid)
	e.ACL = &registry.ACLPolicy{
		Default: registry.ACLDefaultDeny,
		Allow:   []registry.ACLEntry{{ID: "j", Secret: "pw"}},
	}
	if err := d.reg.Put(e); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	src := testUDP("10.3.0.1")
	for i := 0; i < aclIPShortMax; i++ {
		if d.decideAccess(aid, remote, "nope", src) {
			t.Fatalf("wrong password allowed at %d", i)
		}
	}
	if d.decideAccess(aid, remote, "pw", src) {
		t.Fatal("correct password must not be evaluated while IP is locked")
	}
	other := testUDP("10.3.0.2")
	if !d.decideAccess(aid, remote, "pw", other) {
		t.Fatal("other IP with correct password must pass")
	}
}

func TestDecideAccess_nodeAdminBypassesAgentIPGate(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ra.addEntry("allow", aclEntryReq{Secret: "pw"}); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	src := testUDP("10.3.0.9")
	for i := 0; i < aclIPShortMax+2; i++ {
		d.decideAccess(d.nodeAddr, newTestAddr(t), "nope", src)
	}
	if !d.decideAccess(d.nodeAddr, remote, "pw", src) {
		t.Fatal("remote-admin correct password must still work; agent IP gate must not apply")
	}
}
