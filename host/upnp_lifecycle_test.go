// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/natsense"
)

func TestInvalidateNetworkCaches_forcesUPnPRenew(t *testing.T) {
	t.Parallel()
	h := &Host{
		sense: natsense.NewSense(1),
		node:  &dht.Node{},
	}
	h.upnpURL = "quic://1.2.3.4:4121"
	h.upnpExtPort = 4121
	h.upnpInternalPort = 4121
	h.upnpInternalClient = "192.168.1.10"
	h.upnpRenewAfter = time.Now().Add(30 * time.Minute)
	h.upnpFailStreak = 4
	h.upnpFailRetryAfter = time.Now().Add(15 * time.Minute)

	h.InvalidateNetworkCaches()

	h.upnpMu.Lock()
	defer h.upnpMu.Unlock()
	if h.upnpURL != "quic://1.2.3.4:4121" {
		t.Fatalf("Invalidate must keep session URL, got %q", h.upnpURL)
	}
	if !h.upnpRenewAfter.IsZero() {
		t.Fatalf("Invalidate must clear upnpRenewAfter to force renew, got %v", h.upnpRenewAfter)
	}
	if h.upnpFailStreak != 0 || !h.upnpFailRetryAfter.IsZero() {
		t.Fatalf("Invalidate must clear fail backoff: streak=%d retryAfter=%v",
			h.upnpFailStreak, h.upnpFailRetryAfter)
	}
	if h.hasV4 != (outboundIPv4() != nil) || h.hasV6 != (outboundIPv6() != nil) {
		t.Fatalf("Invalidate must refresh family caps: hasV4=%v hasV6=%v", h.hasV4, h.hasV6)
	}
}

func TestUpnpFailDelay(t *testing.T) {
	t.Parallel()
	want := []time.Duration{
		upnpFailBackoffBase,     // streak 0 → 1m
		2 * upnpFailBackoffBase, // 2m
		4 * upnpFailBackoffBase, // 4m
		8 * upnpFailBackoffBase, // 8m
		upnpFailBackoffMax,      // 15m cap
		upnpFailBackoffMax,      // stay capped
	}
	for streak, w := range want {
		if got := upnpFailDelay(streak); got != w {
			t.Fatalf("upnpFailDelay(%d) = %v, want %v", streak, got, w)
		}
	}
}

func TestNoteUPnPFail_exponential(t *testing.T) {
	t.Parallel()
	h := &Host{}
	h.upnpMu.Lock()
	d0 := h.noteUPnPFailLocked()
	s1 := h.upnpFailStreak
	after0 := h.upnpFailRetryAfter
	h.upnpMu.Unlock()
	if d0 != upnpFailBackoffBase || s1 != 1 {
		t.Fatalf("first fail: delay=%v streak=%d, want %v / 1", d0, s1, upnpFailBackoffBase)
	}
	if !after0.After(time.Now()) {
		t.Fatal("FailRetryAfter must be in the future")
	}

	h.upnpMu.Lock()
	d1 := h.noteUPnPFailLocked()
	s2 := h.upnpFailStreak
	h.clearUPnPFailLocked()
	h.upnpMu.Unlock()
	if d1 != 2*upnpFailBackoffBase || s2 != 2 {
		t.Fatalf("second fail: delay=%v streak=%d, want 2m / 2", d1, s2)
	}
	if h.upnpFailStreak != 0 || !h.upnpFailRetryAfter.IsZero() {
		t.Fatal("clearUPnPFailLocked must reset streak and retryAfter")
	}
}

func TestClearUPnP_runsCleanupOnce(t *testing.T) {
	t.Parallel()
	h := &Host{}
	calls := 0
	h.upnpURL = "quic://1.2.3.4:4121"
	h.upnpExtPort = 4121
	h.upnpCleanup = func() { calls++ }

	h.clearUPnP(true)
	h.clearUPnP(true)

	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls)
	}
	if h.upnpURL != "" || h.upnpExtPort != 0 {
		t.Fatalf("state not cleared: url=%q extPort=%d", h.upnpURL, h.upnpExtPort)
	}
}

func TestTryRenewUPnP_incompleteStateClears(t *testing.T) {
	t.Parallel()
	h := &Host{log: slog.Default()}
	h.upnpURL = "quic://1.2.3.4:4121"
	// extPort unset — incomplete session state

	u, ok := h.tryRenewUPnP(context.Background(), "192.168.1.10", time.Now())
	if ok || u != "" {
		t.Fatalf("tryRenewUPnP incomplete = (%q, %v), want empty", u, ok)
	}
	if h.upnpURL != "" {
		t.Fatal("incomplete session must clear upnpURL")
	}
}

func TestUpnpCached_hit(t *testing.T) {
	t.Parallel()
	h := &Host{}
	h.upnpURL = "quic://1.2.3.4:4121"
	h.upnpRenewAfter = time.Now().Add(10 * time.Minute)

	u, ok := h.upnpCached(time.Now())
	if !ok || u != h.upnpURL {
		t.Fatalf("upnpCached = (%q, %v), want cache hit", u, ok)
	}
}
