// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"testing"

	"github.com/a2al/a2al/internal/registry"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNoteActingAgentOnlyWhenRegistered(t *testing.T) {
	d := newTestDaemon(t)
	_, aid := testSyncIdentity(t)

	if _, err := d.resolveAgentAID(aid.String()); err != nil {
		t.Fatal(err)
	}
	if d.aidHasHeartbeat(aid) {
		t.Fatal("unregistered aid must not record liveness")
	}

	if err := d.reg.Put(&registry.Entry{AID: aid}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.resolveAgentAID(aid.String()); err != nil {
		t.Fatal(err)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("registered group actor must record liveness")
	}
}

func TestNoteActingAgentIgnoresNodeIdentity(t *testing.T) {
	d := newTestDaemon(t)
	d.noteActingAgent(d.nodeAddr)
	if d.aidHasHeartbeat(d.nodeAddr) {
		t.Fatal("node identity is not a registered agent")
	}
}

func TestEmptyAIDDoesNotHeartbeatAnotherIdentity(t *testing.T) {
	d := newTestDaemon(t)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.resolveAgentAID(""); err == nil {
		t.Fatal("empty aid: want error")
	}
	if d.aidHasHeartbeat(aid) {
		t.Fatal("empty aid must not record liveness for a registered identity")
	}
}

func TestGroupListRecordsHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.mcpGroupList(context.Background(), nil, &mcp.CallToolParamsFor[mcpGroupListArgs]{
		Arguments: mcpGroupListArgs{AID: aid.String()},
	}); err != nil {
		t.Fatal(err)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("group_list as a registered agent must record liveness")
	}
}

func TestAgentGetDoesNotRecordHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execAgentGet(context.Background(), aid.String()); err != nil {
		t.Fatal(err)
	}
	if d.aidHasHeartbeat(aid) {
		t.Fatal("agent get is inspection, not presence")
	}
}

func TestStatusDoesNotRecordHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	_ = d.execStatus()
	if d.aidHasHeartbeat(aid) {
		t.Fatal("status has no acting agent")
	}
}

func TestEventsPollRecordsHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	d.evtLog = NewEventLog()
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.mcpEventsPoll(context.Background(), nil, &mcp.CallToolParamsFor[mcpEventsPollArgs]{
		Arguments: mcpEventsPollArgs{AID: aid.String()},
	}); err != nil {
		t.Fatal(err)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("events_poll as a registered agent must record liveness")
	}
}

func TestMailboxPollRecordsHeartbeatBeforeNetwork(t *testing.T) {
	d := newTestDaemon(t)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = d.execMailboxPoll(ctx, aid.String())
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("mailbox poll must record liveness once the local agent is confirmed")
	}
}

func TestFetchRecordsHeartbeatOnlyForRegisteredLocal(t *testing.T) {
	d := newTestDaemon(t)
	priv, local := testSyncIdentity(t)
	_, remote := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: local, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = d.execFetch(ctx, d.nodeAddr, remote, fetchReq{Path: "/"})
	if d.aidHasHeartbeat(d.nodeAddr) {
		t.Fatal("default node local_aid must not record agent liveness")
	}
	_, _ = d.execFetch(ctx, local, remote, fetchReq{Path: "/"})
	if !d.aidHasHeartbeat(local) {
		t.Fatal("fetch as a registered local agent must record liveness")
	}
}

func TestResolveRemoteDoesNotRecordHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = d.execResolve(ctx, aid.String())
	if d.aidHasHeartbeat(aid) {
		t.Fatal("resolve treats aid as remote")
	}
}
