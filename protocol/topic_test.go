// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"strings"
	"testing"
)

func TestMarshalTopicPayload_roundtrip(t *testing.T) {
	p := TopicPayload{
		Version:   1,
		Topic:     "ai/test",
		Name:      "n",
		Protocols: []string{"mcp"},
		Tags:      []string{"a"},
		Brief:     "hi",
		Meta:      map[string]any{"k": "v"},
	}
	b, err := MarshalTopicPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := ParseTopicRecord(SignedRecord{RecType: RecTypeTopic, Payload: b})
	if err != nil {
		t.Fatal(err)
	}
	if tp.Topic != "ai/test" || tp.Name != "n" {
		t.Fatalf("%+v", tp)
	}
}

func TestMarshalTopicPayload_briefTooLong(t *testing.T) {
	_, err := MarshalTopicPayload(TopicPayload{Topic: "t", Brief: strings.Repeat("世", MaxTopicBriefRunes+1)})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFilterTopicEntries(t *testing.T) {
	entries := []TopicEntry{
		{Topic: "t", Protocols: []string{"mcp", "grpc"}, Tags: []string{"gpu", "fast"}},
		{Topic: "t", Protocols: []string{"grpc"}, Tags: []string{"gpu"}},
		{Topic: "t", Protocols: []string{"mcp"}, Tags: []string{"cheap"}},
	}

	// nil filter returns all
	if got := FilterTopicEntries(entries, nil); len(got) != 3 {
		t.Fatalf("nil filter: want 3, got %d", len(got))
	}

	// protocol filter (OR semantics)
	f := &DiscoverFilter{Protocols: []string{"mcp"}}
	got := FilterTopicEntries(entries, f)
	if len(got) != 2 {
		t.Fatalf("proto filter: want 2, got %d", len(got))
	}

	// tag filter (AND semantics: all tags must match)
	f2 := &DiscoverFilter{Tags: []string{"gpu", "fast"}}
	got2 := FilterTopicEntries(entries, f2)
	if len(got2) != 1 {
		t.Fatalf("tag filter: want 1, got %d", len(got2))
	}

	// combined: protocol OR mcp, tag gpu (must have both conditions)
	f3 := &DiscoverFilter{Protocols: []string{"mcp"}, Tags: []string{"gpu"}}
	got3 := FilterTopicEntries(entries, f3)
	if len(got3) != 1 {
		t.Fatalf("combined filter: want 1, got %d", len(got3))
	}
}
