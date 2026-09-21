// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPendingCounts_unconsumedOnly(t *testing.T) {
	store := newMailboxStore("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var aidA, aidB a2al.Address
	aidA[0], aidB[0] = 1, 2

	if got := store.PendingCounts(); len(got) != 0 {
		t.Fatalf("empty store: %v", got)
	}

	var id1, id2, id3 [32]byte
	id1[0], id2[0], id3[0] = 10, 11, 12
	store.Put(id1, MailboxStoreEntry{RecipientAID: aidA, TTLExpires: 1 << 40})
	store.Put(id2, MailboxStoreEntry{RecipientAID: aidA, TTLExpires: 1 << 40})
	store.Put(id3, MailboxStoreEntry{RecipientAID: aidB, TTLExpires: 1 << 40})

	got := store.PendingCounts()
	if got[aidA] != 2 || got[aidB] != 1 {
		t.Fatalf("counts %v", got)
	}

	store.MarkConsumed(id1)
	store.MarkConsumed(id2)
	got = store.PendingCounts()
	if _, ok := got[aidA]; ok {
		t.Fatalf("fully consumed AID must be omitted: %v", got)
	}
	if got[aidB] != 1 {
		t.Fatalf("counts %v", got)
	}
}

// The snapshot is scoped to the registry, so the node identity never shows up:
// it cannot send or poll mail, hence can never have anything pending.
func TestPendingSnapshot_registeredAgentsOnly(t *testing.T) {
	d := newTestDaemon(t)
	ctx := context.Background()

	if got := d.pendingSnapshot(ctx, nil); got != nil {
		t.Fatalf("nothing pending: %v", got)
	}

	aid := newTestAgent(t, d)
	var id, nodeID [32]byte
	id[0], nodeID[0] = 1, 2
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})
	d.mboxStore.Put(nodeID, MailboxStoreEntry{RecipientAID: d.nodeAddr, TTLExpires: 1 << 40})

	got := d.pendingSnapshot(ctx, nil)
	if len(got) != 1 {
		t.Fatalf("snapshot %v want one entry", got)
	}
	per, ok := got[aid.String()].(map[string]any)
	if !ok || per["mailbox"] != 1 {
		t.Fatalf("snapshot %v", got)
	}
	if _, leaked := got[d.nodeAddr.String()]; leaked {
		t.Fatal("node identity must not appear in pending")
	}
}

func TestPendingSnapshot_multipleAgents(t *testing.T) {
	d := newTestDaemon(t)
	ctx := context.Background()
	aidA := newTestAgent(t, d)
	aidB := newTestAgent(t, d)

	var a1, b1 [32]byte
	a1[0], b1[0] = 1, 2
	d.mboxStore.Put(a1, MailboxStoreEntry{RecipientAID: aidA, TTLExpires: 1 << 40})
	d.mboxStore.Put(b1, MailboxStoreEntry{RecipientAID: aidB, TTLExpires: 1 << 40})

	if got := d.pendingSnapshot(ctx, nil); len(got) != 2 {
		t.Fatalf("snapshot %v want both agents", got)
	}
	d.mboxStore.MarkConsumed(a1)
	got := d.pendingSnapshot(ctx, nil)
	if len(got) != 1 {
		t.Fatalf("snapshot %v want only the remaining agent", got)
	}
	if _, ok := got[aidB.String()]; !ok {
		t.Fatalf("snapshot %v missing aidB", got)
	}
}

// The hitch must reach every tool, so assert one tool from mcp.go (inline result
// construction) and one from group_mcp.go (mcpOK), proving the middleware does
// not depend on either builder.
func TestMCP_pendingHitch_bothResultBuilders(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)
	aid := newTestAgent(t, d)
	var id [32]byte
	id[0] = 7
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})

	cs := newMCPClientSession(t, buildMCPServer(d))
	ctx := context.Background()

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"a2al_agents_list", map[string]any{}},              // mcp.go, inline
		{"group_list", map[string]any{"aid": aid.String()}}, // group_mcp.go, mcpOK
	} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if res.IsError {
			t.Fatalf("%s: tool error %v", tc.tool, res.Content)
		}
		sc, ok := res.StructuredContent.(map[string]any)
		if !ok {
			t.Fatalf("%s: structured content %T", tc.tool, res.StructuredContent)
		}
		pending, ok := sc["pending"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no pending in %v", tc.tool, sc)
		}
		per, ok := pending[aid.String()].(map[string]any)
		if !ok {
			t.Fatalf("%s: pending missing aid: %v", tc.tool, pending)
		}
		if got := per["mailbox"]; got != float64(1) && got != 1 {
			t.Fatalf("%s: mailbox = %v (%T), want 1", tc.tool, got, got)
		}
	}
}

func TestMCP_pendingHitch_absentWhenNothingWaiting(t *testing.T) {
	d := newTestDaemon(t)
	newTestAgent(t, d)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agents_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sc := res.StructuredContent.(map[string]any)
	if _, present := sc["pending"]; present {
		t.Fatalf("pending must be omitted when nothing waits: %v", sc)
	}
}

// A failed call must not carry unrelated state.
func TestMCP_pendingHitch_notOnError(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	var id [32]byte
	id[0] = 7
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})

	cs := newMCPClientSession(t, buildMCPServer(d))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "group_list",
		Arguments: map[string]any{}, // missing aid → tool error
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected a tool error")
	}
	if sc, ok := res.StructuredContent.(map[string]any); ok {
		if _, present := sc["pending"]; present {
			t.Fatalf("error result must not carry pending: %v", sc)
		}
	}
}

// A single-resource carrier reports only the identity it is about, but renders
// the same shape as the overview carriers.
func TestPendingFor_singleIdentityScope(t *testing.T) {
	d := newTestDaemon(t)
	aidA := newTestAgent(t, d)
	aidB := newTestAgent(t, d)

	var a1, b1 [32]byte
	a1[0], b1[0] = 1, 2
	d.mboxStore.Put(a1, MailboxStoreEntry{RecipientAID: aidA, TTLExpires: 1 << 40})
	d.mboxStore.Put(b1, MailboxStoreEntry{RecipientAID: aidB, TTLExpires: 1 << 40})

	got := d.pendingFor(aidA)
	if len(got) != 1 {
		t.Fatalf("pendingFor(A) = %v, want exactly one entry", got)
	}
	per, ok := got[aidA.String()].(map[string]any)
	if !ok || per["mailbox"] != 1 {
		t.Fatalf("pendingFor(A) = %v", got)
	}
	if _, leaked := got[aidB.String()]; leaked {
		t.Fatalf("sibling identity leaked into single-resource scope: %v", got)
	}

	// Same shape as the overview scope, only narrower.
	if overview := d.pendingSnapshot(context.Background(), nil); len(overview) != 2 {
		t.Fatalf("overview = %v, want both agents", overview)
	}

	d.mboxStore.MarkConsumed(a1)
	if got := d.pendingFor(aidA); got != nil {
		t.Fatalf("pendingFor(A) after consume = %v, want nil", got)
	}
	if got := d.pendingFor(aidB); len(got) != 1 {
		t.Fatalf("pendingFor(B) = %v, want one entry", got)
	}
}

func TestAddPendingHitch_doesNotOverwrite(t *testing.T) {
	out := map[string]any{"pending": "tool-owned"}
	addPendingHitch(out, map[string]any{"aid": map[string]any{"mailbox": 3}})
	if out["pending"] != "tool-owned" {
		t.Fatalf("existing key overwritten: %v", out)
	}

	out = map[string]any{}
	addPendingHitch(out, nil)
	if _, present := out["pending"]; present {
		t.Fatalf("empty snapshot must add nothing: %v", out)
	}
}

func TestSSE_pendingHitch_perAID(t *testing.T) {
	d := newTestDaemon(t)
	d.evtLog = NewEventLog()
	aidA := newTestAgent(t, d)
	aidB := newTestAgent(t, d)
	var a1, b1 [32]byte
	a1[0], b1[0] = 1, 2
	d.mboxStore.Put(a1, MailboxStoreEntry{RecipientAID: aidA, TTLExpires: 1 << 40})
	d.mboxStore.Put(b1, MailboxStoreEntry{RecipientAID: aidB, TTLExpires: 1 << 40})

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)

	frame := readSSEPendingFrame(t, srv.URL+"/agents/"+aidA.String()+"/events", http.Header{
		"Last-Event-ID": []string{"99"},
	})
	if strings.Contains(frame, "id:") {
		t.Fatalf("pending frame must not carry id: %q", frame)
	}
	pending := parsePendingData(t, frame)
	if len(pending) != 1 {
		t.Fatalf("pending %v want only A", pending)
	}
	if _, leaked := pending[aidB.String()]; leaked {
		t.Fatalf("sibling leaked: %v", pending)
	}
	per := pending[aidA.String()].(map[string]any)
	if per["mailbox"] != float64(1) {
		t.Fatalf("mailbox %v", per["mailbox"])
	}

	// types= filter applies to EventLog only; the envelope still goes out.
	frame = readSSEPendingFrame(t, srv.URL+"/agents/"+aidA.String()+"/events?types=group.unread", nil)
	if parsePendingData(t, frame)[aidA.String()] == nil {
		t.Fatal("types filter must not drop the pending envelope")
	}

	d.mboxStore.MarkConsumed(a1)
	prefix := readSSEPrefix(t, srv.URL+"/agents/"+aidA.String()+"/events", nil, 400*time.Millisecond)
	if strings.Contains(prefix, "event: pending") {
		t.Fatalf("consumed inventory must omit pending: %q", prefix)
	}
}

func TestSSE_pendingHitch_global(t *testing.T) {
	d := newTestDaemon(t)
	d.evtLog = NewEventLog()
	aid := newTestAgent(t, d)
	var id [32]byte
	id[0] = 3
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)
	pending := parsePendingData(t, readSSEPendingFrame(t, srv.URL+"/events", nil))
	if pending[aid.String()] == nil {
		t.Fatalf("global SSE missing pending: %v", pending)
	}
}

func TestPendingShape_appSourceWithoutMailbox(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	d.RegisterPending("app_x", func(a a2al.Address) int {
		if a == aid {
			return 2
		}
		return 0
	})
	got := d.pendingSnapshot(context.Background(), nil)
	per, ok := got[aid.String()].(map[string]any)
	if !ok || per["app_x"] != 2 {
		t.Fatalf("snapshot %v", got)
	}
	if _, has := per["mailbox"]; has {
		t.Fatalf("mailbox must stay omitted: %v", per)
	}
}

func TestPendingShape_sourceZeroOmitted(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	d.RegisterPending("app_x", func(a2al.Address) int { return 0 })
	if got := d.pendingSnapshot(context.Background(), nil); got != nil {
		t.Fatalf("all-zero must omit pending: %v", got)
	}
	var id [32]byte
	id[0] = 1
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})
	got := d.pendingSnapshot(context.Background(), nil)
	per := got[aid.String()].(map[string]any)
	if per["mailbox"] != 1 {
		t.Fatalf("%v", per)
	}
	if _, has := per["app_x"]; has {
		t.Fatalf("zero source key must omit: %v", per)
	}
}

func TestPendingShape_mailboxAndSourceTogether(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	var id [32]byte
	id[0] = 1
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})
	d.RegisterPending("app_x", func(a a2al.Address) int {
		if a == aid {
			return 4
		}
		return 0
	})
	per := d.pendingSnapshot(context.Background(), nil)[aid.String()].(map[string]any)
	if per["mailbox"] != 1 || per["app_x"] != 4 {
		t.Fatalf("%v", per)
	}
}

func TestPendingShape_sourceCannotExpandScope(t *testing.T) {
	d := newTestDaemon(t)
	newTestAgent(t, d)
	d.RegisterPending("app_x", func(a2al.Address) int { return 9 })
	got := d.pendingSnapshot(context.Background(), nil)
	if _, leaked := got[d.nodeAddr.String()]; leaked {
		t.Fatalf("source must not add the node identity: %v", got)
	}
}

func TestRegisterPending_mailboxKeyIgnored(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	d.RegisterPending("mailbox", func(a2al.Address) int { return 7 })
	if got := d.pendingSnapshot(context.Background(), nil); got != nil {
		t.Fatalf("reserved mailbox key must not register: %v", got)
	}
	var id [32]byte
	id[0] = 1
	d.mboxStore.Put(id, MailboxStoreEntry{RecipientAID: aid, TTLExpires: 1 << 40})
	per := d.pendingSnapshot(context.Background(), nil)[aid.String()].(map[string]any)
	if per["mailbox"] != 1 {
		t.Fatalf("built-in mailbox overwritten: %v", per)
	}
}

func TestMCP_pendingHitch_appSource(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	d.RegisterPending("app_x", func(a a2al.Address) int {
		if a == aid {
			return 3
		}
		return 0
	})
	cs := newMCPClientSession(t, buildMCPServer(d))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agents_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sc := res.StructuredContent.(map[string]any)
	pending := sc["pending"].(map[string]any)
	per := pending[aid.String()].(map[string]any)
	if got := per["app_x"]; got != float64(3) && got != 3 {
		t.Fatalf("app_x=%v", got)
	}
}

func TestSSE_pendingHitch_appSource(t *testing.T) {
	d := newTestDaemon(t)
	d.evtLog = NewEventLog()
	aid := newTestAgent(t, d)
	d.RegisterPending("app_x", func(a a2al.Address) int {
		if a == aid {
			return 1
		}
		return 0
	})
	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)
	pending := parsePendingData(t, readSSEPendingFrame(t, srv.URL+"/agents/"+aid.String()+"/events", nil))
	per := pending[aid.String()].(map[string]any)
	if per["app_x"] != float64(1) {
		t.Fatalf("%v", per)
	}
}

func readSSEPendingFrame(t *testing.T, url string, extra http.Header) string {
	t.Helper()
	body := readSSEUntil(t, url, extra, 2*time.Second, func(s string) bool {
		i := strings.Index(s, "event: pending\n")
		if i < 0 {
			return false
		}
		chunk := s[i:]
		return strings.Contains(chunk, "data:") && strings.Contains(chunk, "\n\n")
	})
	start := strings.Index(body, "event: pending\n")
	if start < 0 {
		t.Fatalf("no pending frame in %q", body)
	}
	rest := body[start:]
	end := strings.Index(rest, "\n\n")
	if end < 0 {
		t.Fatalf("unterminated pending frame in %q", body)
	}
	return rest[:end+2]
}

func readSSEPrefix(t *testing.T, url string, extra http.Header, wait time.Duration) string {
	t.Helper()
	return readSSEUntil(t, url, extra, wait, func(string) bool { return false })
}

func readSSEUntil(t *testing.T, url string, extra http.Header, wait time.Duration, done func(string) bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range extra {
		req.Header[k] = vs
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	var buf strings.Builder
	for {
		line, err := r.ReadString('\n')
		buf.WriteString(line)
		if done(buf.String()) {
			cancel()
			return buf.String()
		}
		if err != nil {
			return buf.String()
		}
	}
}

func parsePendingData(t *testing.T, frame string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(frame, "\n") {
		if strings.HasPrefix(line, "data: ") {
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatalf("no data line in %q", frame)
	return nil
}
