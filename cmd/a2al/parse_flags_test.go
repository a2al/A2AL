// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"strings"
	"testing"
)

func TestParseFlagsStrict_unknownFlag(t *testing.T) {
	var aid, after, limit string
	_, err := parseFlagsStrict(
		[]string{"--aid", "me", "--peer", "them", "--before-seq", "50"},
		map[string]*string{"--aid": &aid, "--after-seq": &after, "--limit": &limit, "--peer": new(string)},
		0,
	)
	if err == nil || !strings.Contains(err.Error(), "unknown flag --before-seq") {
		t.Fatalf("got %v", err)
	}
}

func TestParseFlagsStrict_missingValue(t *testing.T) {
	var limit string
	_, err := parseFlagsStrict([]string{"--limit"}, map[string]*string{"--limit": &limit}, 0)
	if err == nil || !strings.Contains(err.Error(), "missing value for --limit") {
		t.Fatalf("got %v", err)
	}
}

func TestParseFlagsStrict_objectPutPositional(t *testing.T) {
	var aid string
	pos, err := parseFlagsStrict([]string{"--aid", "me", "file.bin"}, map[string]*string{"--aid": &aid}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if aid != "me" || len(pos) != 1 || pos[0] != "file.bin" {
		t.Fatalf("aid=%q pos=%v", aid, pos)
	}
}

func TestParseFlagsStrict_extraPositional(t *testing.T) {
	var aid string
	_, err := parseFlagsStrict([]string{"--aid", "me", "a", "b"}, map[string]*string{"--aid": &aid}, 1)
	if err == nil || !strings.Contains(err.Error(), "unexpected argument b") {
		t.Fatalf("got %v", err)
	}
}

func TestParseFlagsStrict_equalsAndDashDash(t *testing.T) {
	var aid, limit string
	pos, err := parseFlagsStrict(
		[]string{"--aid=me", "--limit=10", "--", "--not-a-flag"},
		map[string]*string{"--aid": &aid, "--limit": &limit},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if aid != "me" || limit != "10" || len(pos) != 1 || pos[0] != "--not-a-flag" {
		t.Fatalf("aid=%q limit=%q pos=%v", aid, limit, pos)
	}
}
