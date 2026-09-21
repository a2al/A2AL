// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"

	"github.com/a2al/a2al"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pendingVisibleAIDs answers "which AIDs may this caller be told about".
//
// Today it returns every registered agent: MCP is not yet authenticated, so a
// session can already act as any local identity and the telling scope matches
// the acting scope. ctx and ss are unused for that reason, but stay in the
// signature because per-session authorisation is coming — when it lands, the
// authorised set is read from the session or its token and only this function
// changes. Callers (the MCP middleware and the two HTTP overview handlers) stay
// as they are.
//
// Same scope as syncLocalReceiveKeys: registry only, no node identity. The node
// AID has no readable mailbox because mailbox send/poll both require a registry
// entry, so it can never have anything pending.
func (d *Daemon) pendingVisibleAIDs(ctx context.Context, ss *mcp.ServerSession) []a2al.Address {
	_, _ = ctx, ss
	d.regMu.RLock()
	defer d.regMu.RUnlock()
	entries := d.reg.List()
	out := make([]a2al.Address, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.AID)
	}
	return out
}

const pendingKeyMailbox = "mailbox"

// RegisterPending adds an application count source under key. n is called with
// each visible AID at hitch time; n<=0 omits the key. n=nil removes the source.
// "mailbox" is reserved for mailbox_store.
func (d *Daemon) RegisterPending(key string, n func(a2al.Address) int) {
	if key == "" || key == pendingKeyMailbox {
		return
	}
	if n == nil {
		d.pendingSources.delete(key)
		return
	}
	d.pendingSources.put(key, n)
}

func (d *Daemon) clonePendingSources() map[string]func(a2al.Address) int {
	return d.pendingSources.clone()
}

// pendingSnapshot reports what each visible AID still has waiting locally, in
// the wire shape {"<aid>": {"mailbox": N, ...}}. Returns nil when nothing is
// pending anywhere in scope, which is what lets every carrier omit the field.
//
// Purely local: never touches the DHT and never mutates ConsumedAt.
func (d *Daemon) pendingSnapshot(ctx context.Context, ss *mcp.ServerSession) map[string]any {
	return d.pendingShape(d.pendingVisibleAIDs(ctx, ss))
}

// pendingFor is pendingSnapshot narrowed to one identity, for single-resource
// carriers such as GET /agents/{aid}.
//
// Authorisation for those carriers is not decided here — it belongs to the
// per-agent token slot in withAgentMiddleware, which already gates the rest of
// the resource. Once that slot is filled it gates this disclosure with it, so a
// caller cannot read one identity's pending count through another's resource.
func (d *Daemon) pendingFor(aid a2al.Address) map[string]any {
	return d.pendingShape([]a2al.Address{aid})
}

// pendingShape merges mailbox_store with registered sources for scope.
// Only the breadth of scope differs across carriers, never the structure.
func (d *Daemon) pendingShape(scope []a2al.Address) map[string]any {
	if len(scope) == 0 {
		return nil
	}
	var mailbox map[a2al.Address]int
	if d.mboxStore != nil {
		mailbox = d.mboxStore.PendingCounts()
	}
	sources := d.clonePendingSources()
	var out map[string]any
	for _, aid := range scope {
		bag := map[string]any{}
		if n := mailbox[aid]; n > 0 {
			bag[pendingKeyMailbox] = n
		}
		for key, fn := range sources {
			if n := fn(aid); n > 0 {
				bag[key] = n
			}
		}
		if len(bag) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]any)
		}
		out[aid.String()] = bag
	}
	return out
}
