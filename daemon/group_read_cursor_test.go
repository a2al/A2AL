// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/a2al/a2al/group"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// group_read's after_seq and the replica's read_cursor are two different things,
// and this pins the boundary between them because it is the one most easily
// eroded: after_seq is an exclusive seq bound supplied per call and never
// remembered, while read_cursor is a persisted bookmark that only the caller
// advances.
//
// Reading must not advance the bookmark. The advance rate is the single knob a
// consumer holds over how often it is notified (房间改进计划 §310-318), and an
// auditor that reads the whole log without ever being interrupted depends on
// reading being free of side effects.
func TestGroupReadDoesNotMoveReadCursor(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)

	priv, aid := testSyncIdentity(t)
	s, err := d.groups.Create(aid, priv, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	gid := s.ID()

	for _, body := range []string{"one", "two", "three"} {
		e, err := group.NewEntry(priv, aid, s.Heads(), "msg", group.WithBody([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(e, nil); err != nil {
			t.Fatal(err)
		}
	}

	read := func(t *testing.T, args mcpGroupReadArgs) map[string]any {
		t.Helper()
		args.GroupID = hex.EncodeToString(gid[:])
		args.AID = aid.String()
		res, err := d.mcpGroupRead(context.Background(), nil,
			&mcp.CallToolParamsFor[mcpGroupReadArgs]{Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return res.StructuredContent
	}
	entryCount := func(m map[string]any) int {
		return len(m["entries"].([]map[string]any))
	}

	total := s.MaxSeq()

	// Omitted after_seq means 0, which is "from the start" — not "where I left
	// off". Reading the whole log must leave the bookmark at 0.
	got := read(t, mcpGroupReadArgs{})
	if n := entryCount(got); uint64(n) != total {
		t.Fatalf("after_seq omitted returned %d entries, want the whole log (%d) from the start", n, total)
	}
	if got["read_cursor"].(uint64) != 0 {
		t.Fatalf("reading moved the bookmark to %v, want it untouched at 0", got["read_cursor"])
	}
	if got["unread_count"].(uint64) != 0 {
		t.Fatalf("unread=%v: own appends must never count as unread", got["unread_count"])
	}

	// An explicit after_seq is an exclusive bound: after_seq=N yields seq > N.
	got = read(t, mcpGroupReadArgs{AfterSeq: total - 1})
	if n := entryCount(got); n != 1 {
		t.Fatalf("after_seq=%d returned %d entries, want exactly the one after it", total-1, n)
	}
	if got["scanned_to_seq"].(uint64) != total {
		t.Fatalf("scanned_to_seq=%v, want %d", got["scanned_to_seq"], total)
	}

	// Reading past the end is empty, not an error, and still moves nothing.
	got = read(t, mcpGroupReadArgs{AfterSeq: total})
	if n := entryCount(got); n != 0 {
		t.Fatalf("after_seq at head returned %d entries, want 0", n)
	}

	// Only group_mark_read moves the bookmark.
	if _, err := s.AdvanceCursor(total); err != nil {
		t.Fatal(err)
	}
	got = read(t, mcpGroupReadArgs{})
	if uint64(entryCount(got)) != total {
		t.Fatal("advancing the bookmark must not change what after_seq=0 returns")
	}
	if got["read_cursor"].(uint64) != total {
		t.Fatalf("read_cursor=%v, want the advanced value %d reported back", got["read_cursor"], total)
	}
}
