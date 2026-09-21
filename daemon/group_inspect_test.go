// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/internal/registry"
)

func TestGroupInspectDoesNotRecordHeartbeatOrMoveCursor(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)

	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	s, err := d.groups.Create(aid, priv, "inspect-room")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	sid := s.ID()
	gid := hex.EncodeToString(sid[:])

	e, err := group.NewEntry(priv, aid, s.Heads(), "msg", group.WithBody([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(e, nil); err != nil {
		t.Fatal(err)
	}
	cursorBefore := s.ReadCursor()
	unreadBefore := s.UnreadCount(aid)

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/agents/" + aid.String()

	getJSON := func(t *testing.T, path string) map[string]any {
		t.Helper()
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	list := getJSON(t, "/groups")
	groups, _ := list["groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("groups=%v, want 1", list["groups"])
	}
	head := getJSON(t, "/groups/"+gid)
	if _, ok := head["unread_count"]; ok {
		t.Fatal("inspect head must not expose unread_count")
	}
	if _, ok := head["read_cursor"]; ok {
		t.Fatal("inspect head must not expose read_cursor")
	}
	if _, ok := head["pending"]; ok {
		t.Fatal("inspect must not hitch pending")
	}
	if head["title"] != "inspect-room" {
		t.Fatalf("title=%v", head["title"])
	}

	ents := getJSON(t, "/groups/"+gid+"/entries?after_seq=0")
	if _, ok := ents["unread_count"]; ok {
		t.Fatal("inspect entries must not expose unread_count")
	}
	entries, _ := ents["entries"].([]any)
	if len(entries) < 1 {
		t.Fatal("want at least the genesis or hello entry")
	}

	if d.aidHasHeartbeat(aid) {
		t.Fatal("inspect GET must not record liveness")
	}
	if s.ReadCursor() != cursorBefore {
		t.Fatalf("read_cursor moved from %d to %d", cursorBefore, s.ReadCursor())
	}
	if s.UnreadCount(aid) != unreadBefore {
		t.Fatalf("unread_count changed from %d to %d", unreadBefore, s.UnreadCount(aid))
	}
}

func TestGroupInspectUnknownGroupIs404(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	_, aid := testSyncIdentity(t)

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/agents/" + aid.String() + "/groups/" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

func TestGroupInspectEntriesAfterSeq(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	priv, aid := testSyncIdentity(t)
	s, err := d.groups.Create(aid, priv, "seq")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, body := range []string{"a", "b", "c"} {
		e, err := group.NewEntry(priv, aid, s.Heads(), "msg", group.WithBody([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(e, nil); err != nil {
			t.Fatal(err)
		}
	}
	maxSeq := s.MaxSeq()
	sid := s.ID()
	gid := hex.EncodeToString(sid[:])

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/agents/" + aid.String() + "/groups/" + gid +
		"/entries?after_seq=" + strconv.FormatUint(maxSeq-1, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	entries, _ := out["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("after_seq=head-1 returned %d, want 1", len(entries))
	}
}
