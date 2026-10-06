// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/internal/registry"
)

func doJSON(t *testing.T, d *Daemon, method, path, raw string) (int, map[string]any) {
	t.Helper()
	var body *strings.Reader
	if raw != "" {
		body = strings.NewReader(raw)
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	d.routes().ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

func TestGroupAppendHTTP(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	d.cfg.FilesRoot = t.TempDir()

	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	s, err := d.groups.Create(aid, priv, "append-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	sid := s.ID()
	gid := hex.EncodeToString(sid[:])
	base := "/agents/" + aid.String() + "/groups/" + gid

	if d.aidHasHeartbeat(aid) {
		t.Fatal("setup must not record liveness")
	}

	code, out := doJSON(t, d, http.MethodPost, base+"/append", `{"text":"web-hello"}`)
	if code != http.StatusOK {
		t.Fatalf("append text status %d %v", code, out)
	}
	if out["entry_id"] == nil || out["seq"] == nil {
		t.Fatalf("append resp %v", out)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("append POST must record liveness")
	}

	code, page := doJSON(t, d, http.MethodGet, base+"/entries?after_seq=0", "")
	if code != http.StatusOK {
		t.Fatalf("entries status %d", code)
	}
	if _, ok := page["unread_count"]; ok {
		t.Fatal("inspect entries must not expose unread_count")
	}
	found := false
	for _, it := range page["entries"].([]any) {
		m := it.(map[string]any)
		body, _ := m["body"].(string)
		raw, _ := base64.StdEncoding.DecodeString(body)
		if string(raw) == "web-hello" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("appended text missing from inspect entries")
	}

	code, _ = doJSON(t, d, http.MethodPost, base+"/append",
		`{"text":"x","object_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("xor status %d", code)
	}
	code, _ = doJSON(t, d, http.MethodPost, base+"/append", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty status %d", code)
	}

	unknown := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	code, _ = doJSON(t, d, http.MethodPost, "/agents/"+aid.String()+"/groups/"+unknown+"/append", `{"text":"nope"}`)
	if code != http.StatusNotFound {
		t.Fatalf("unknown group status %d", code)
	}

	oid, _, _, err := d.ingestCASObject(aid, bytes.NewReader([]byte("file-bytes")), "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	oidHex := hex.EncodeToString(oid[:])
	code, out = doJSON(t, d, http.MethodPost, base+"/append", `{"object_id":"`+oidHex+`","name":"note.txt"}`)
	if code != http.StatusOK {
		t.Fatalf("append file status %d %v", code, out)
	}

	_, page2 := doJSON(t, d, http.MethodGet, base+"/entries?after_seq=0", "")
	foundFile := false
	for _, it := range page2["entries"].([]any) {
		m := it.(map[string]any)
		if m["kind"] != "file" {
			continue
		}
		body, _ := m["body"].(string)
		raw, _ := base64.StdEncoding.DecodeString(body)
		var desc map[string]any
		if err := json.Unmarshal(raw, &desc); err != nil {
			t.Fatal(err)
		}
		if desc["name"] != "note.txt" {
			t.Fatalf("file name %v", desc["name"])
		}
		if g, _ := desc["grant"].(string); g == "" {
			t.Fatal("file grant missing")
		}
		if m["ref"] != oidHex {
			t.Fatalf("ref %v want %s", m["ref"], oidHex)
		}
		foundFile = true
	}
	if !foundFile {
		t.Fatal("file entry missing")
	}
}

func TestGroupAppendHTTPUnregisteredIs404(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	_, aid := testSyncIdentity(t)
	gid := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	code, _ := doJSON(t, d, http.MethodPost, "/agents/"+aid.String()+"/groups/"+gid+"/append", `{"text":"x"}`)
	if code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", code)
	}
}

func TestGroupLeaveHTTP(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)

	privA, aidA := testSyncIdentity(t)
	privB, aidB := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aidA, OpPriv: privA}); err != nil {
		t.Fatal(err)
	}
	if err := d.reg.Put(&registry.Entry{AID: aidB, OpPriv: privB}); err != nil {
		t.Fatal(err)
	}
	sA, err := d.groups.Create(aidA, privA, "leave-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sA.Close() })
	gidArr := sA.ID()
	gid := hex.EncodeToString(gidArr[:])
	leaveA := "/agents/" + aidA.String() + "/groups/" + gid + "/leave"
	leaveB := "/agents/" + aidB.String() + "/groups/" + gid + "/leave"

	code, _ := doJSON(t, d, http.MethodPost, leaveA, `{}`)
	if code != http.StatusConflict {
		t.Fatalf("creator leave status %d, want 409", code)
	}

	inv, err := group.NewEntry(privA, aidA, sA.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(aidB)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sA.Append(inv, nil); err != nil {
		t.Fatal(err)
	}
	sB, err := d.groups.Join(aidB, gidArr, aidA, "leave-room")
	if err != nil {
		t.Fatal(err)
	}
	ents, _, _, err := sA.Read(0, 50, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, er := range ents {
		if err := sB.Append(er.Entry, nil); err != nil {
			t.Fatal(err)
		}
	}

	code, out := doJSON(t, d, http.MethodPost, leaveB, `{}`)
	if code != http.StatusOK {
		t.Fatalf("member leave status %d %v", code, out)
	}
	code, list := doJSON(t, d, http.MethodGet, "/agents/"+aidB.String()+"/groups", "")
	if code != http.StatusOK {
		t.Fatalf("list status %d", code)
	}
	groups, _ := list["groups"].([]any)
	if len(groups) != 0 {
		t.Fatalf("left replica still listed: %v", list["groups"])
	}
}

func TestGroupFilePrefetchSameDaemon(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	d.cfg.FilesRoot = t.TempDir()

	privA, aidA := testSyncIdentity(t)
	privB, aidB := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aidA, OpPriv: privA}); err != nil {
		t.Fatal(err)
	}
	if err := d.reg.Put(&registry.Entry{AID: aidB, OpPriv: privB}); err != nil {
		t.Fatal(err)
	}
	sA, err := d.groups.Create(aidA, privA, "file-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sA.Close() })
	gidArr := sA.ID()
	gid := hex.EncodeToString(gidArr[:])

	inv, err := group.NewEntry(privA, aidA, sA.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(aidB)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sA.Append(inv, nil); err != nil {
		t.Fatal(err)
	}
	sB, err := d.groups.Join(aidB, gidArr, aidA, "file-room")
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

	id, _, _, err := d.ingestCASObject(aidA, bytes.NewReader([]byte("group-file")), "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	oidHex := hex.EncodeToString(id[:])
	code, out := doJSON(t, d, http.MethodPost,
		"/agents/"+aidA.String()+"/groups/"+gid+"/append",
		`{"object_id":"`+oidHex+`","name":"note.txt"}`)
	if code != http.StatusOK {
		t.Fatalf("append file status %d %v", code, out)
	}

	if _, err := d.alignWithPeer(context.Background(), aidA, gidArr, aidB, sA); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := d.lookupLocalObject(aidB, id); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inbound group file was not prefetched onto the receiver")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		rec, ok := d.casRec(aidA, id)
		if ok && fetchedHas(rec.Served, aidB.String()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sender Served %v", rec.Served)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
