// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

func testAID(t *testing.T, hexPair string) a2al.Address {
	t.Helper()
	aid, err := a2al.ParseAddress(strings.ToLower("A0" + strings.Repeat(hexPair, 20)))
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

func TestConnPool_userSkipsBackoff(t *testing.T) {
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return nil, false, errors.New("dial fail")
	}, slog.Default())

	ctx := context.Background()
	local := testAID(t, "ab")
	remote := testAID(t, "cd")

	if _, _, err := p.acquire(ctx, local, remote, nil, false, false); err == nil {
		t.Fatal("want auto dial error")
	}
	if dials != 1 {
		t.Fatalf("dials=%d want 1", dials)
	}

	_, _, err := p.acquire(ctx, local, remote, nil, false, false)
	if err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatalf("want backoff, got %v", err)
	}
	if dials != 1 {
		t.Fatalf("auto must not redial in backoff, dials=%d", dials)
	}

	if _, _, err := p.acquire(ctx, local, remote, nil, false, true); err == nil {
		t.Fatal("want user dial error")
	}
	if dials != 2 {
		t.Fatalf("user must skip backoff, dials=%d", dials)
	}

	if _, _, err := p.acquire(ctx, local, remote, nil, false, true); err == nil {
		t.Fatal("want user dial error")
	}
	if dials != 3 {
		t.Fatalf("user fail must not write backoff, dials=%d", dials)
	}
}
