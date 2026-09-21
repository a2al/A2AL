// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"time"

	"github.com/a2al/a2al"
)

// alignAID is the liveness-edge entry: enumerate local groups and make them due.
func (d *Daemon) alignAID(_ context.Context, aid a2al.Address) {
	d.kickAlignAID(aid)
}

func (d *Daemon) alignAliveAIDs(_ context.Context) {
	if d.groups == nil || d.reg == nil {
		return
	}
	d.regMu.RLock()
	entries := d.reg.List()
	d.regMu.RUnlock()
	for _, e := range entries {
		if e == nil || !d.aidHasHeartbeat(e.AID) {
			continue
		}
		d.kickAlignAID(e.AID)
	}
}

func (d *Daemon) aidHasHeartbeat(aid a2al.Address) bool {
	d.heartbeatMu.Lock()
	t, ok := d.heartbeatAt[aid]
	d.heartbeatMu.Unlock()
	return ok && !t.IsZero() && time.Since(t) < heartbeatTTL
}
