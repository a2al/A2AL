// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

func TestCASPublicHashAloneDenied(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	stranger := newTestAgent(t, d)
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	ok, status, _ := casGetRoundtrip(t, d, holder, stranger, id, "")
	if !ok {
		t.Fatal("public ACL should open the stream")
	}
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}
}

func TestCASPendingInviteDenied(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), holder.String(), peer.String(), ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("early"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(holder, id)
	if err != nil {
		t.Fatal(err)
	}
	d.noteObjectCabinet(holder, id, cabinetChat, peer.String())
	ok, status, _ := casGetRoundtrip(t, d, holder, peer, id, grant)
	if !ok {
		t.Fatal("token should open the stream")
	}
	if status != http.StatusForbidden {
		t.Fatalf("out_pending status %d, want 403", status)
	}
}

func TestCASPutNeverSharedRemoteDeniedLocalOK(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	stranger := newTestAgent(t, d)
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("unshared"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	ok, status, _ := casGetRoundtrip(t, d, holder, stranger, id, "token")
	if !ok || status != http.StatusForbidden {
		t.Fatalf("remote ok=%v status=%d", ok, status)
	}

	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/agents/" + holder.String() + "/cas/" + hex.EncodeToString(id[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "unshared" {
		t.Fatalf("identity get status=%d body=%q", resp.StatusCode, body)
	}
}

func TestCASGroupMemberGetsFile(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	gid, gidHex := mustGroupTwo(t, d, a, b)

	path := filepath.Join(t.TempDir(), "g.bin")
	if err := os.WriteFile(path, []byte("room-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(a, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(a, id)
	if err != nil {
		t.Fatal(err)
	}
	d.noteObjectCabinet(a, id, cabinetGroup, gidHex)

	ok, status, body := casGetRoundtrip(t, d, a, b, id, grant)
	if !ok || status != 200 || body != "room-file" {
		t.Fatalf("member ok=%v status=%d body=%q", ok, status, body)
	}

	stranger := newTestAgent(t, d)
	ok, status, _ = casGetRoundtrip(t, d, a, stranger, id, grant)
	if !ok || status != http.StatusForbidden {
		t.Fatalf("stranger ok=%v status=%d", ok, status)
	}

	sA, err := d.groups.Open(a, gid)
	if err != nil {
		t.Fatal(err)
	}
	privA := d.reg.Get(a).OpPriv
	rev, err := group.NewEntry(privA, a, sA.Heads(), group.KindRevoke,
		group.WithBody(group.EncodeMemberBody(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sA.Append(rev, nil); err != nil {
		t.Fatal(err)
	}
	ok, status, _ = casGetRoundtrip(t, d, a, b, id, grant)
	if !ok || status != http.StatusForbidden {
		t.Fatalf("revoked ok=%v status=%d", ok, status)
	}
}

func TestCASGroupOtherHolderServesMember(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	c := newTestAgent(t, d)
	gid, gidHex := mustGroupTwo(t, d, a, b)
	mustJoinGroup(t, d, a, c, gid)
	copyGroupLog(t, d, a, b, gid)

	path := filepath.Join(t.TempDir(), "g.bin")
	if err := os.WriteFile(path, []byte("from-b"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(a, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.mapObject(b, id, path, 6); err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(b, id)
	if err != nil {
		t.Fatal(err)
	}
	d.noteObjectCabinet(b, id, cabinetGroup, gidHex)

	ok, status, body := casGetRoundtrip(t, d, b, c, id, grant)
	if !ok || status != 200 || body != "from-b" {
		t.Fatalf("other holder ok=%v status=%d body=%q", ok, status, body)
	}
}

func mustGroupTwo(t *testing.T, d *Daemon, a, b a2al.Address) ([32]byte, string) {
	t.Helper()
	if d.groups == nil {
		d.groups = newGroupManager(d.dataDir, d.log)
	}
	privA := d.reg.Get(a).OpPriv
	sA, err := d.groups.Create(a, privA, "cab-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sA.Close() })
	gid := sA.ID()
	mustJoinGroup(t, d, a, b, gid)
	return gid, hex.EncodeToString(gid[:])
}

func mustJoinGroup(t *testing.T, d *Daemon, creator, member a2al.Address, gid [32]byte) {
	t.Helper()
	sA, err := d.groups.Open(creator, gid)
	if err != nil {
		t.Fatal(err)
	}
	privA := d.reg.Get(creator).OpPriv
	inv, err := group.NewEntry(privA, creator, sA.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(member)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sA.Append(inv, nil); err != nil {
		t.Fatal(err)
	}
	sB, err := d.groups.Join(member, gid, creator, "cab-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sB.Close() })
	ents, _, _, err := sA.Read(0, 50, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, er := range ents {
		if err := sB.Append(er.Entry, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func copyGroupLog(t *testing.T, d *Daemon, src, dst a2al.Address, gid [32]byte) {
	t.Helper()
	sSrc, err := d.groups.Open(src, gid)
	if err != nil {
		t.Fatal(err)
	}
	sDst, err := d.groups.Open(dst, gid)
	if err != nil {
		t.Fatal(err)
	}
	ents, _, _, err := sSrc.Read(0, 200, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, er := range ents {
		if err := sDst.Append(er.Entry, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCASNoteObjectCabinetDedup(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	var id [32]byte
	id[0] = 3
	d.noteObjectCabinet(aid, id, cabinetChat, peer.String())
	d.noteObjectCabinet(aid, id, cabinetChat, peer.String())
	rec, ok := d.casRec(aid, id)
	if !ok || len(rec.Resources) != 1 {
		t.Fatalf("%+v ok=%v", rec, ok)
	}
}

func TestCASMapObjectPreservesResources(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	var id [32]byte
	id[0] = 4
	d.noteObjectCabinet(aid, id, cabinetChat, peer.String())
	path := filepath.Join(t.TempDir(), "p.bin")
	if err := os.WriteFile(path, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.mapObject(aid, id, path, 1); err != nil {
		t.Fatal(err)
	}
	rec, ok := d.casRec(aid, id)
	if !ok || len(rec.Resources) != 1 || rec.Path != path {
		t.Fatalf("%+v ok=%v", rec, ok)
	}
}
