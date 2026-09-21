// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseCASPath(t *testing.T) {
	var id [32]byte
	id[0], id[31] = 0xab, 0xcd
	p := CASPath(id)
	got, ok := ParseCASPath(p)
	if !ok || got != id {
		t.Fatalf("ParseCASPath(%q) = %x ok=%v", p, got, ok)
	}
	if _, ok := ParseCASPath("/cas/zz"); ok {
		t.Fatal("expected reject")
	}
	h := hex.EncodeToString(id[:])
	if !strings.Contains(CASPath(id), h) {
		t.Fatal("CASPath missing hash")
	}
}
