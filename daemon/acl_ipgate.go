// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"net"
	"sync"
	"time"
)

// Ordinary-agent ACL anti-brute (S3). Process-local; not persisted; never
// written to the holder's deny list. Node remote admin does not use this.
const (
	aclIPShortWindow = 10 * time.Second
	aclIPShortMax    = 8
	aclIPLongWindow  = 15 * time.Minute
	aclIPLongMax     = 30
	aclIPLock        = 12 * time.Minute
	aclIPMaxTracked  = 512
)

type aclIPEntry struct {
	shortEnd    time.Time
	shortN      int
	longEnd     time.Time
	longN       int
	lockedUntil time.Time
}

type aclIPGate struct {
	mu  sync.Mutex
	m   map[string]*aclIPEntry
	now func() time.Time
}

func newACLIPGate() *aclIPGate {
	return &aclIPGate{m: make(map[string]*aclIPEntry), now: time.Now}
}

func aclIPKey(src net.Addr) string {
	raw := addrIP(src)
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func (g *aclIPGate) locked(src net.Addr) bool {
	if g == nil {
		return false
	}
	key := aclIPKey(src)
	if key == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.pruneLocked(now)
	e := g.m[key]
	return e != nil && now.Before(e.lockedUntil)
}

func (g *aclIPGate) noteFail(src net.Addr) {
	if g == nil {
		return
	}
	key := aclIPKey(src)
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.pruneLocked(now)
	e := g.m[key]
	if e == nil {
		e = &aclIPEntry{}
		g.m[key] = e
	}
	if e.shortEnd.IsZero() || now.After(e.shortEnd) {
		e.shortEnd = now.Add(aclIPShortWindow)
		e.shortN = 0
	}
	if e.longEnd.IsZero() || now.After(e.longEnd) {
		e.longEnd = now.Add(aclIPLongWindow)
		e.longN = 0
	}
	e.shortN++
	e.longN++
	if e.shortN >= aclIPShortMax || e.longN >= aclIPLongMax {
		e.lockedUntil = now.Add(aclIPLock)
	}
}

func (g *aclIPGate) noteOK(src net.Addr) {
	if g == nil {
		return
	}
	key := aclIPKey(src)
	if key == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.m, key)
}

func (g *aclIPGate) pruneLocked(now time.Time) {
	if len(g.m) <= aclIPMaxTracked {
		return
	}
	for k, e := range g.m {
		if now.After(e.lockedUntil) && now.After(e.shortEnd) && now.After(e.longEnd) {
			delete(g.m, k)
		}
	}
	if len(g.m) > aclIPMaxTracked {
		g.m = make(map[string]*aclIPEntry)
	}
}
