// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"time"

	"github.com/a2al/a2al"
)

// Join-scoped pull after group_join created an empty replica. This is the
// joining AID finishing the call it just made, not a general heartbeat probe.
// After give-up, outbound stops; an inbound fill from the creator can still
// complete the replica.
var (
	joinProbeInterval    = 10 * time.Second
	joinProbeTempAfter   = 1 * time.Minute
	joinProbeGiveUpAfter = 3 * time.Minute
	joinProbeDialTimeout = 8 * time.Second
)

type joinProbe struct {
	cancel  context.CancelFunc
	inviter a2al.Address
	peers   []a2al.Address
	lastErr string
}

func (d *Daemon) startJoinProbe(aid a2al.Address, gid [32]byte, inviter a2al.Address, peers []a2al.Address, lastErr error) {
	if d.groups == nil {
		return
	}
	reason := ""
	if lastErr != nil {
		reason = lastErr.Error()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &joinProbe{cancel: cancel, inviter: inviter, peers: uniqueJoinPeers(peers, aid), lastErr: reason}

	d.joinProbeMu.Lock()
	if d.joinProbes == nil {
		d.joinProbes = make(map[alignGroupKey]*joinProbe)
	}
	key := alignGroupKey{aid, gid}
	if old := d.joinProbes[key]; old != nil && old.cancel != nil {
		old.cancel()
	}
	d.joinProbes[key] = p
	d.joinProbeMu.Unlock()

	go d.runJoinProbe(ctx, aid, gid, p)
}

func uniqueJoinPeers(peers []a2al.Address, self a2al.Address) []a2al.Address {
	seen := make(map[a2al.Address]struct{}, len(peers))
	var out []a2al.Address
	for _, p := range peers {
		if p == (a2al.Address{}) || p == self {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (d *Daemon) stopJoinProbe(aid a2al.Address, gid [32]byte) {
	d.joinProbeMu.Lock()
	defer d.joinProbeMu.Unlock()
	key := alignGroupKey{aid, gid}
	if p := d.joinProbes[key]; p != nil && p.cancel != nil {
		p.cancel()
	}
	delete(d.joinProbes, key)
}

func (d *Daemon) replicaHasEntries(aid a2al.Address, gid [32]byte) bool {
	if d.groups == nil {
		return false
	}
	s, err := d.groups.Open(aid, gid)
	if err != nil {
		return false
	}
	return s.EntryCount() > 0
}

func (d *Daemon) runJoinProbe(ctx context.Context, aid a2al.Address, gid [32]byte, p *joinProbe) {
	defer func() {
		d.joinProbeMu.Lock()
		key := alignGroupKey{aid, gid}
		if d.joinProbes[key] == p {
			delete(d.joinProbes, key)
		}
		d.joinProbeMu.Unlock()
	}()

	ticker := time.NewTicker(joinProbeInterval)
	defer ticker.Stop()
	temp := time.NewTimer(joinProbeTempAfter)
	defer temp.Stop()
	giveUp := time.NewTimer(joinProbeGiveUpAfter)
	defer giveUp.Stop()
	tempSent := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.replicaHasEntries(aid, gid) {
				return
			}
			if err := d.joinProbeDial(ctx, aid, gid, p.peers); err != nil {
				p.lastErr = err.Error()
			}
			if d.replicaHasEntries(aid, gid) {
				return
			}
		case <-temp.C:
			if tempSent || d.replicaHasEntries(aid, gid) {
				continue
			}
			tempSent = true
			d.sendJoinNotice(ctx, aid, p.inviter, gid, joinNoticeDeferred, p.lastErr)
		case <-giveUp.C:
			if d.replicaHasEntries(aid, gid) {
				return
			}
			d.sendJoinNotice(ctx, aid, p.inviter, gid, joinNoticeGaveUp, p.lastErr)
			return
		}
	}
}

func (d *Daemon) joinProbeDial(ctx context.Context, aid a2al.Address, gid [32]byte, peers []a2al.Address) error {
	var last error
	for _, peer := range peers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dctx, cancel := context.WithTimeout(ctx, joinProbeDialTimeout)
		_, err := d.SyncGroupWith(dctx, gid, aid, peer)
		cancel()
		if err == nil {
			return nil
		}
		last = err
	}
	return last
}
