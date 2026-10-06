// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/a2al/a2al/internal/registry"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file implements check V1 of doc-local/A2AL 语义表达准则.md: outward-facing
// text may not name anything that does not exist in the code.
//
// Drift here is more expensive than drift in a document. A caller builds calls
// against the missing concept, fails, and then invents its own replacement —
// which is how three participants in the field tests ended up with three
// mutually incompatible doorbells. Both drift instances the guideline recorded
// (a tool suggesting "after receiving a Poke", an event list promising "group
// invitations") would have been caught here.

// removedConcepts are names that string literals must no longer use. Add an
// entry whenever a concept is deleted or renamed; the reason is part of the
// failure message so the next reader does not have to re-derive it.
// Terms are listed in the spelling callers would actually see, including the
// prose spellings: the two drift instances on record were "receiving a Poke"
// and "Events include group invitations", neither of which is an identifier.
var removedConcepts = []struct{ term, why string }{
	{"Poke", "removed 2026-09-17: coming back up to date is the returning AID's own job (see alignAID), not something a best-effort envelope can guarantee"},
	{"GroupPoke", "see Poke"},
	{"group_poke", "see Poke"},
	{"group.invited", "no such event: the room events are group.unread, group.mentioned and group.appended"},
	{"group invitation", "not an event: invitations arrive as ordinary mailbox notes, so point callers at a2al_mailbox_list"},
	{"group.synced", "no such event: observe alignment through group_head or group_members instead"},
	{"events?after_seq", "SSE replay cursor is last_event_id (and Last-Event-ID); after_seq belongs to events_poll and group_read"},
}

// v1ScanDirs are the packages whose string literals reach a caller, either as
// a tool description, an error, help text or session instructions.
var v1ScanDirs = []string{".", "../cmd/a2al", "../protocol", "../group", "../host"}

const v1SelfFile = "semantics_v1_test.go"

// findRemovedConcepts returns the removed terms named by s.
func findRemovedConcepts(s string) []string {
	var hits []string
	for _, rc := range removedConcepts {
		if strings.Contains(s, rc.term) {
			hits = append(hits, rc.term)
		}
	}
	return hits
}

// TestV1ScannerCatchesKnownDrift pins the scanner against the two drift
// instances that actually shipped, so the denylist cannot quietly decay into a
// check that passes because it looks for nothing real.
func TestV1ScannerCatchesKnownDrift(t *testing.T) {
	shipped := []string{
		"Manually trigger one round of QUIC sync with a specific peer AID for a Group. Useful after receiving a Poke or to bootstrap a new member.",
		"Return queued daemon events for a local agent since a given sequence number. Events include group invitations, mailbox messages, sync completions, and other async notifications.",
		"For real-time delivery use the SSE endpoint GET /agents/{aid}/events?after_seq=N instead.",
	}
	for _, s := range shipped {
		if hits := findRemovedConcepts(s); len(hits) == 0 {
			t.Errorf("scanner no longer catches known drift: %q", s)
		}
	}
	// And it must not fire on the text that replaced them.
	for _, s := range []string{mcpInstructions} {
		if hits := findRemovedConcepts(s); len(hits) != 0 {
			t.Errorf("false positive on current instructions: %v", hits)
		}
	}
}

func TestV1NoRemovedConceptsInStringLiterals(t *testing.T) {
	for _, dir := range v1ScanDirs {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			return fi.Name() != v1SelfFile // this file names the terms on purpose
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		for _, pkg := range pkgs {
			for path, f := range pkg.Files {
				// Only string literals: comments explaining why something was
				// removed are worth keeping, and are not shown to callers.
				ast.Inspect(f, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					s, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						s = lit.Value
					}
					for _, term := range findRemovedConcepts(s) {
						why := ""
						for _, rc := range removedConcepts {
							if rc.term == term {
								why = rc.why
							}
						}
						t.Errorf("%s:%d: string literal names removed concept %q — %s",
							path, fset.Position(lit.Pos()).Line, term, why)
					}
					return true
				})
			}
		}
	}
}

// toolRefPattern matches anything shaped like one of our tool names.
var toolRefPattern = regexp.MustCompile(`\b(?:a2al|group)_[a-z_]+\b`)

// v1NonToolIdentifiers are tool-shaped tokens that are legitimately not tools.
// Keep this list short: every addition is a place where a caller could mistake
// a field for something callable.
var v1NonToolIdentifiers = map[string]bool{
	"group_id": true,
}

// TestV1ToolReferencesExist checks the other half of V1: every tool a
// description or the session instructions tells the caller to call must
// actually be registered. A caller that follows a dangling reference does not
// stop — it improvises.
func TestV1ToolReferencesExist(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	registered := make(map[string]bool, len(res.Tools))
	for _, tl := range res.Tools {
		registered[tl.Name] = true
	}

	texts := map[string]string{"<session instructions>": mcpInstructions}
	for _, tl := range res.Tools {
		texts[tl.Name] = tl.Description
	}

	for origin, text := range texts {
		for _, ref := range toolRefPattern.FindAllString(text, -1) {
			if registered[ref] || v1NonToolIdentifiers[ref] {
				continue
			}
			t.Errorf("%s refers to %q, which is not a registered tool", origin, ref)
		}
	}
}

// TestV1RejectionErrorsAreActionable is the V4 spot-check from the guideline:
// a rejection must say what to do next, not merely that something was wrong.
// It exercises the rejections a caller hits first, on a daemon with no
// registered agent and no replicas.
func TestV1RejectionErrorsAreActionable(t *testing.T) {
	d := newTestDaemon(t)

	// aid is mandatory and never inferred: it names the authority the call acts
	// as, so it must be stated even when this daemon holds a single identity.
	// The error still has to say where a valid one comes from.
	_, err := d.resolveAgentAID("")
	if err == nil {
		t.Fatal("empty aid: want error")
	}
	if !strings.Contains(err.Error(), "a2al_agents_list") {
		t.Errorf("empty-aid error does not say how to find a valid aid: %q", err)
	}

	// But it must not answer with the list itself. Enumerating the identities
	// held here is precisely what a caller with no right to them must not get,
	// and an error is an easy place to leak it by accident.
	priv, aid := testSyncIdentity(t)
	if err := d.reg.Put(&registry.Entry{AID: aid, OpPriv: priv}); err != nil {
		t.Fatal(err)
	}
	_, err = d.resolveAgentAID("")
	if err == nil {
		t.Fatal("empty aid with one identity registered: want error, not an inferred actor")
	}
	if strings.Contains(err.Error(), aid.String()) {
		t.Errorf("empty-aid error enumerates a locally held identity: %q", err)
	}

	// Missing group_id: must name where a valid one comes from.
	if _, err := parseGroupID(""); err == nil {
		t.Fatal("empty group_id: want error")
	} else if !strings.Contains(err.Error(), "group_list") {
		t.Errorf("empty group_id error does not say where to get one: %q", err)
	}

	// Malformed group_id: must state the expected shape and where to get one.
	_, err = parseGroupID("not-hex")
	if err == nil {
		t.Fatal("malformed group_id: want error")
	}
	for _, want := range []string{"64 hex", "group_list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("malformed group_id error does not mention %q: %q", want, err)
		}
	}
}
