// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"time"

	"github.com/a2al/a2al"
)

const pathSettleTimeout = 70 * time.Second

// pathSettler drains one kind of debt for a Mode A pair that just became live.
// It must use getLive only, must not acquire, and must not fail the caller
// that populated the pool.
type pathSettler func(ctx context.Context, local, remote a2al.Address)

func (d *Daemon) registerPathSettler(fn pathSettler) {
	if d == nil || fn == nil {
		return
	}
	d.pathSettlersMu.Lock()
	d.pathSettlers = append(d.pathSettlers, fn)
	d.pathSettlersMu.Unlock()
}

func (d *Daemon) notePathLive(local, remote a2al.Address) {
	if d == nil {
		return
	}
	go d.settlePath(local, remote)
}

func (d *Daemon) settlePath(local, remote a2al.Address) {
	if !d.aidHasHeartbeat(local) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pathSettleTimeout)
	defer cancel()
	d.pathSettlersMu.Lock()
	fns := append([]pathSettler(nil), d.pathSettlers...)
	d.pathSettlersMu.Unlock()
	for _, fn := range fns {
		fn(ctx, local, remote)
	}
}
