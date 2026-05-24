// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"slices"
	"testing"
)

// TestEffectiveICESignalURLs verifies the merge order and deduplication of
// effectiveICESignalURLs: routing candidates preferred over bootstrap fallback,
// config wins over both.
func TestEffectiveICESignalURLs(t *testing.T) {
	ks := newMemKS(t)
	h, err := New(Config{
		KeyStore:       ks,
		PrivateKey:     ks.priv,
		ListenAddr:     "127.0.0.1:0",
		QUICListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })

	t.Run("empty when no candidates", func(t *testing.T) {
		h.bootstrapHubURLs = nil
		h.routingHubCandidates = nil
		if got := h.effectiveICESignalURLs(); len(got) != 0 {
			t.Fatalf("want empty, got %v", got)
		}
	})

	t.Run("bootstrap only", func(t *testing.T) {
		h.bootstrapHubURLs = []string{"ws://boot1:4121", "ws://boot2:4121"}
		h.routingHubCandidates = nil
		got := h.effectiveICESignalURLs()
		if !slices.Equal(got, h.bootstrapHubURLs) {
			t.Fatalf("want %v, got %v", h.bootstrapHubURLs, got)
		}
	})

	t.Run("routing preferred over bootstrap", func(t *testing.T) {
		h.bootstrapHubURLs = []string{"ws://boot1:4121"}
		h.routingHubCandidates = []string{"ws://peer1:4121", "ws://peer2:4121"}
		got := h.effectiveICESignalURLs()
		// routing candidates must appear before bootstrap
		idxPeer1 := slices.Index(got, "ws://peer1:4121")
		idxBoot := slices.Index(got, "ws://boot1:4121")
		if idxPeer1 < 0 || idxBoot < 0 {
			t.Fatalf("missing expected URLs: %v", got)
		}
		if idxPeer1 > idxBoot {
			t.Errorf("routing candidate should precede bootstrap: got %v", got)
		}
	})

	t.Run("dedup across routing and bootstrap", func(t *testing.T) {
		shared := "ws://shared:4121"
		h.routingHubCandidates = []string{shared, "ws://peer1:4121"}
		h.bootstrapHubURLs = []string{shared, "ws://boot1:4121"}
		got := h.effectiveICESignalURLs()
		count := 0
		for _, u := range got {
			if u == shared {
				count++
			}
		}
		if count != 1 {
			t.Errorf("shared URL appears %d times (want 1): %v", count, got)
		}
	})

	t.Run("dedup within routing candidates", func(t *testing.T) {
		h.routingHubCandidates = []string{"ws://peer1:4121", "ws://peer1:4121"}
		h.bootstrapHubURLs = nil
		got := h.effectiveICESignalURLs()
		count := 0
		for _, u := range got {
			if u == "ws://peer1:4121" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("duplicate in routing not deduped: %v", got)
		}
	})

	t.Run("config ICESignalURL wins over all", func(t *testing.T) {
		h.cfg.ICESignalURL = "ws://config:9999"
		h.routingHubCandidates = []string{"ws://peer1:4121"}
		h.bootstrapHubURLs = []string{"ws://boot1:4121"}
		got := h.effectiveICESignalURLs()
		if len(got) != 1 || got[0] != "ws://config:9999" {
			t.Errorf("want config URL only, got %v", got)
		}
		h.cfg.ICESignalURL = "" // reset
	})

	t.Run("config ICESignalURLs wins over all", func(t *testing.T) {
		h.cfg.ICESignalURLs = []string{"ws://cfg1:9999", "ws://cfg2:9999"}
		h.routingHubCandidates = []string{"ws://peer1:4121"}
		h.bootstrapHubURLs = []string{"ws://boot1:4121"}
		got := h.effectiveICESignalURLs()
		if !slices.Equal(got, h.cfg.ICESignalURLs) {
			t.Errorf("want config URLs %v, got %v", h.cfg.ICESignalURLs, got)
		}
		h.cfg.ICESignalURLs = nil // reset
	})
}
