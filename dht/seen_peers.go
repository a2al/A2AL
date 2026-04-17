// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
)

const seenPeersTTL = 7 * 24 * time.Hour

// loadSeenPeers reads seen_peers.dat into n.seenPeers (hex_node_id unix_last_seen).
// Lines that are malformed or older than 7d are silently skipped.
// A missing or unreadable file is not an error.
func (n *Node) loadSeenPeers(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // file absent or unreadable — start fresh
	}
	defer f.Close()
	cutoff := time.Now().Add(-seenPeersTTL)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		raw, err := hex.DecodeString(parts[0])
		if err != nil || len(raw) != len(a2al.NodeID{}) {
			continue
		}
		secs, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		t := time.Unix(secs, 0)
		if t.Before(cutoff) {
			continue
		}
		var nid a2al.NodeID
		copy(nid[:], raw)
		n.seenPeers.LoadOrStore(nid, t)
	}
}

// flushSeenPeers writes seenPeers entries within the 7d window (last_seen per line).
func (n *Node) flushSeenPeers(path string) error {
	cutoff := time.Now().Add(-seenPeersTTL)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	var writeErr error
	n.seenPeers.Range(func(k, v any) bool {
		t := v.(time.Time)
		if t.Before(cutoff) {
			return true // skip expired
		}
		nid := k.(a2al.NodeID)
		_, writeErr = fmt.Fprintf(w, "%s %d\n", hex.EncodeToString(nid[:]), t.Unix())
		return writeErr == nil
	})
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return writeErr
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// startSeenPeersFlusher runs a goroutine that flushes seenPeers hourly and
// on node shutdown. Only called when seenPeersPath is non-empty.
func (n *Node) startSeenPeersFlusher() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if err := n.flushSeenPeers(n.seenPeersPath); err != nil {
					n.log.Debug("seenPeers flush failed", "err", err)
				}
			case <-n.ctx.Done():
				if err := n.flushSeenPeers(n.seenPeersPath); err != nil {
					n.log.Debug("seenPeers final flush failed", "err", err)
				}
				return
			}
		}
	}()
}
