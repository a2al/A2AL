// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group_test

import (
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/group"
)

// testIdentity generates a fresh ed25519 key pair and the corresponding AID.
func testIdentity(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, a2al.Address) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, aid
}

func TestCreateAndOpen(t *testing.T) {
	dir := t.TempDir()
	priv, _, creator := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "test group")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID() == ([32]byte{}) {
		t.Fatal("expected non-zero group ID")
	}
	if s.EntryCount() != 1 {
		t.Fatalf("expected 1 genesis entry, got %d", s.EntryCount())
	}
	if err := s.Close(); err != nil {
		t.Fatal("Close:", err)
	}

	// Re-open and verify the index is rebuilt correctly.
	s2, err := group.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s2.Close()
	if s2.ID() != s.ID() {
		t.Fatal("group ID mismatch after re-open")
	}
	if s2.EntryCount() != 1 {
		t.Fatalf("expected 1 entry after re-open, got %d", s2.EntryCount())
	}
}

func TestAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	heads := s.Heads()
	e1, err := group.NewEntry(priv, creator, heads, "msg", group.WithBody([]byte("hello")))
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if err := s.Append(e1, pub); err != nil {
		t.Fatalf("Append e1: %v", err)
	}

	e2, err := group.NewEntry(priv, creator, s.Heads(), "msg",
		group.WithBody([]byte("world")),
		group.WithReplyTo(e1.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(e2, pub); err != nil {
		t.Fatalf("Append e2: %v", err)
	}

	// genesis + e1 + e2
	if s.EntryCount() != 3 {
		t.Fatalf("expected 3 entries, got %d", s.EntryCount())
	}

	// Read from start (afterSeq=0).
	entries, next, hasMore, err := s.Read(0, 10, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries from Read, got %d", len(entries))
	}
	if hasMore {
		t.Error("hasMore should be false when all entries fit in one page")
	}

	// Read with cursor (skip first entry: afterSeq=1 → start from seq=2).
	page2, _, _, err := s.Read(1, 10, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 entries after cursor seq=1, got %d", len(page2))
	}
	_ = next

	// MaxSeq should equal entry count.
	if s.MaxSeq() != 3 {
		t.Fatalf("MaxSeq expected 3, got %d", s.MaxSeq())
	}
}

// Writing to a group must not make the author's own red dot light up, and must
// not disturb what the author still owes a read to. The earlier implementation
// kept the count honest by pushing the cursor to MaxSeq on every self-append,
// which marked everyone else's pending entries read as a side effect.
func TestUnreadCountExcludesOwnEntriesAndKeepsOthers(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)
	otherPriv, otherPub, other := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	append := func(p ed25519.PrivateKey, author a2al.Address, pk ed25519.PublicKey, text string) {
		t.Helper()
		e, err := group.NewEntry(p, author, s.Heads(), "msg", group.WithBody([]byte(text)))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(e, pk); err != nil {
			t.Fatal(err)
		}
	}

	// Creator reads everything that exists (the genesis entry).
	if _, err := s.AdvanceCursor(s.MaxSeq()); err != nil {
		t.Fatal(err)
	}
	if n := s.UnreadCount(creator); n != 0 {
		t.Fatalf("fully read: unread = %d, want 0", n)
	}

	// Two entries arrive from another member while the creator is not looking.
	append(otherPriv, other, otherPub, "theirs 1")
	append(otherPriv, other, otherPub, "theirs 2")
	if n := s.UnreadCount(creator); n != 2 {
		t.Fatalf("after two foreign entries: unread = %d, want 2", n)
	}

	// The creator now writes. Their own entry is not unread to them, and the
	// two foreign entries must still be owed.
	append(priv, creator, pub, "mine")
	if n := s.UnreadCount(creator); n != 2 {
		t.Fatalf("after self-append: unread = %d, want 2 (own entry must not count, foreign must survive)", n)
	}
	if c := s.ReadCursor(); c != 1 {
		t.Fatalf("self-append moved the read cursor to %d; it must stay at 1", c)
	}

	// Asking the same replica from the other member's perspective: past the
	// cursor (1) sit their own two entries plus the creator's "mine", so only
	// "mine" is unread to them. Real deployments give each AID its own replica
	// and cursor; this just pins down that the filter keys off the author.
	if n := s.UnreadCount(other); n != 1 {
		t.Fatalf("other's view: unread = %d, want 1 (only the creator's entry)", n)
	}

	// UnreadCountUpTo reconstructs the count as of an earlier point, which is
	// what the group.unread edge trigger is built on.
	if n := s.UnreadCountUpTo(creator, 1); n != 0 {
		t.Fatalf("up to seq 1: unread = %d, want 0", n)
	}
	if n := s.UnreadCountUpTo(creator, 2); n != 1 {
		t.Fatalf("up to seq 2: unread = %d, want 1", n)
	}
}

// has_more must mean "the page was cut short by limit", not "the log has more
// entries after the last match". Under a filter the latter is almost always
// true and sends clients paging forever.
func TestReadHasMoreMeansPageTruncated(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, kind := range []string{"note", "msg", "msg", "msg"} {
		e, err := group.NewEntry(priv, creator, s.Heads(), kind, group.WithBody([]byte(kind)))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(e, pub); err != nil {
			t.Fatal(err)
		}
	}

	// The only "note" sits at seq 2 with three entries after it. The scan runs
	// to the end and finds nothing more, so there is no next page.
	entries, next, hasMore, err := s.Read(0, 50, group.ReadFilter{Kind: "note"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("filtered read returned %d entries, want 1", len(entries))
	}
	if hasMore {
		t.Error("has_more is true although the scan reached the end of the log")
	}
	if next != s.MaxSeq() {
		t.Errorf("scannedTo = %d, want %d (end of log)", next, s.MaxSeq())
	}

	// Hitting the limit is the one case that does mean "more".
	page, next, hasMore, err := s.Read(0, 2, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || !hasMore {
		t.Fatalf("limited read: n=%d has_more=%v, want 2/true", len(page), hasMore)
	}
	if next != 2 {
		t.Errorf("scannedTo = %d, want 2", next)
	}
}

func TestBodySizeLimit(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)
	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Body exactly at limit should succeed.
	body := make([]byte, group.MaxEntryBodySize)
	e, err := group.NewEntry(priv, creator, s.Heads(), "msg", group.WithBody(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(e, pub); err != nil {
		t.Fatalf("expected success at body size limit, got: %v", err)
	}

	// Body one byte over limit should fail.
	bigBody := make([]byte, group.MaxEntryBodySize+1)
	e2, err := group.NewEntry(priv, creator, s.Heads(), "msg", group.WithBody(bigBody))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(e2, pub); err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
}

func TestReadFilter(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)
	_, _, other := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Append a msg and a file kind entry.
	msg, _ := group.NewEntry(priv, creator, s.Heads(), "msg", group.WithBody([]byte("hi")))
	_ = s.Append(msg, pub)
	note, _ := group.NewEntry(priv, creator, s.Heads(), "note", group.WithBody([]byte("note")))
	_ = s.Append(note, pub)

	// Filter by kind.
	got, _, _, err := s.Read(0, 100, group.ReadFilter{Kind: "msg"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 msg, got %d", len(got))
	}

	// Filter by author (no other-authored entries).
	got2, _, _, _ := s.Read(0, 100, group.ReadFilter{Author: other})
	if len(got2) != 0 {
		t.Fatalf("expected 0 entries for other author, got %d", len(got2))
	}
}

func TestMissingAndIdempotentAppend(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	e, err := group.NewEntry(priv, creator, s.Heads(), "msg", group.WithBody([]byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(e, pub); err != nil {
		t.Fatal(err)
	}

	// Missing: peer claims to have an entry we don't know about.
	var unknown [32]byte
	unknown[0] = 0xff
	missing := s.Missing([][32]byte{e.ID, unknown})
	if len(missing) != 1 || missing[0] != unknown {
		t.Fatalf("expected [unknown], got %v", missing)
	}

	// Idempotent: appending the same entry again must not error.
	if err := s.Append(e, pub); err != nil {
		t.Fatalf("duplicate Append should be idempotent, got: %v", err)
	}
	if s.EntryCount() != 2 { // genesis + e
		t.Fatalf("entry count changed on duplicate append: %d", s.EntryCount())
	}
}

func TestMembers(t *testing.T) {
	dir := t.TempDir()
	privA, pubA, aidA := testIdentity(t)
	privB, pubB, aidB := testIdentity(t)

	s, err := group.Create(dir, privA, aidA, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// aidA is creator.
	ms, err := s.Members()
	if err != nil {
		t.Fatal(err)
	}
	if ms.Role(aidA) != group.RoleCreator {
		t.Fatalf("expected creator role for aidA, got %v", ms.Role(aidA))
	}
	if ms.Role(aidB) != group.RoleNone {
		t.Fatalf("expected none role for aidB before invite")
	}

	// Invite aidB.
	invite, err := group.NewEntry(privA, aidA, s.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(aidB)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(invite, pubA); err != nil {
		t.Fatal(err)
	}

	ms2, err := s.Members()
	if err != nil {
		t.Fatal(err)
	}
	if ms2.Role(aidB) != group.RoleMember {
		t.Fatalf("expected member role for aidB after invite, got %v", ms2.Role(aidB))
	}

	leave, err := group.NewEntry(privB, aidB, s.Heads(), group.KindRevoke,
		group.WithBody(group.EncodeMemberBody(aidB)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(leave, pubB); err != nil {
		t.Fatal(err)
	}
	ms3, err := s.Members()
	if err != nil {
		t.Fatal(err)
	}
	if ms3.Role(aidB) != group.RoleRevoked {
		t.Fatalf("expected revoked after self-leave, got %v", ms3.Role(aidB))
	}
}

func TestCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	priv, pub, creator := testIdentity(t)

	s, err := group.Create(dir, priv, creator, "recovery test")
	if err != nil {
		t.Fatal(err)
	}
	e, _ := group.NewEntry(priv, creator, s.Heads(), "msg", group.WithBody([]byte("first")))
	_ = s.Append(e, pub)
	_ = s.Close()

	// Corrupt the log by appending a partial record.
	logPath := dir + "/entries.log"
	f, _ := os.OpenFile(logPath, os.O_RDWR|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte{0x00, 0x00, 0x00, 0x10}) // partial header (only 4 bytes)
	_ = f.Close()

	// Re-open should succeed; the partial record must be truncated.
	s2, err := group.Open(dir)
	if err != nil {
		t.Fatalf("Open after corruption: %v", err)
	}
	defer s2.Close()
	if s2.EntryCount() != 2 { // genesis + first entry
		t.Fatalf("expected 2 entries after crash recovery, got %d", s2.EntryCount())
	}
}

func TestDMGroupID(t *testing.T) {
	_, _, aidA := testIdentity(t)
	_, _, aidB := testIdentity(t)

	id1 := group.DMGroupID(aidA, aidB)
	id2 := group.DMGroupID(aidB, aidA)
	if id1 != id2 {
		t.Fatal("DMGroupID is not symmetric")
	}
}

func TestVerifyEntry(t *testing.T) {
	priv, pub, creator := testIdentity(t)
	_, pubOther, _ := testIdentity(t)

	e, err := group.NewEntry(priv, creator, nil, "msg", group.WithBody([]byte("test")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(pub); err != nil {
		t.Fatalf("Verify with correct key: %v", err)
	}
	if err := e.Verify(pubOther); err == nil {
		t.Fatal("Verify with wrong key should fail")
	}
}

func TestEntryBodyAndRef(t *testing.T) {
	priv, pub, creator := testIdentity(t)
	var ref [32]byte
	ref[0] = 1
	e, err := group.NewEntry(priv, creator, nil, "file",
		group.WithBody([]byte(`{"name":"a.pdf","size":3}`)),
		group.WithRef(ref),
	)
	if err != nil {
		t.Fatal(err)
	}
	if e.Ref != ref {
		t.Fatalf("ref mismatch")
	}
	if err := e.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
