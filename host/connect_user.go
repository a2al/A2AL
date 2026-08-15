// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"sort"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// ConnectUserFor dials as localAgent toward expectRemote for a user-initiated
// connect. It races an impression dial against a network Resolve and switches
// only when the remote endpoints actually changed.
//
// impression may be a locally-cached record (or nil). A nil impression falls
// through to ResolveNetwork then ConnectFromRecordFor.
func (h *Host) ConnectUserFor(ctx context.Context, localAgent, expectRemote a2al.Address, impression *protocol.EndpointRecord, opts DialOptions) (quic.Connection, bool, error) {
	if impression == nil {
		er, _, err := h.resolveNetwork(ctx, expectRemote)
		if err != nil {
			return nil, false, err
		}
		return h.ConnectFromRecordFor(ctx, localAgent, expectRemote, er, opts)
	}

	impCtx, impCancel := context.WithCancel(ctx)
	defer impCancel()

	type dialRes struct {
		conn    quic.Connection
		relayed bool
		err     error
	}
	impCh := make(chan dialRes, 1)
	go func() {
		c, r, err := h.ConnectFromRecordFor(impCtx, localAgent, expectRemote, impression, opts)
		impCh <- dialRes{c, r, err}
	}()

	type netRes struct {
		er  *protocol.EndpointRecord
		sr  protocol.SignedRecord
		err error
	}
	netCh := make(chan netRes, 1)
	go func() {
		er, sr, err := h.resolveNetwork(ctx, expectRemote)
		netCh <- netRes{er, sr, err}
	}()

	seed := func(n netRes) {
		if n.err == nil && n.sr.RecType == protocol.RecTypeEndpoint {
			_ = h.node.LocalStorePut(a2al.NodeIDFromAddress(expectRemote), n.sr)
		}
	}

	select {
	case r := <-impCh:
		if r.err == nil {
			return r.conn, r.relayed, nil
		}
		n := <-netCh
		if n.err != nil {
			return nil, false, r.err
		}
		seed(n)
		return h.ConnectFromRecordFor(ctx, localAgent, expectRemote, n.er, opts)

	case n := <-netCh:
		if n.err == nil && endpointDialFingerprint(impression) != endpointDialFingerprint(n.er) {
			impCancel()
			r := <-impCh
			seed(n)
			if r.err == nil {
				return r.conn, r.relayed, nil
			}
			h.log.Debug("connect user: endpoint changed, redial",
				"remote_aid", expectRemote.String())
			return h.ConnectFromRecordFor(ctx, localAgent, expectRemote, n.er, opts)
		}
		r := <-impCh
		seed(n)
		if r.err == nil {
			return r.conn, r.relayed, nil
		}
		if n.err != nil {
			return nil, false, r.err
		}
		return h.ConnectFromRecordFor(ctx, localAgent, expectRemote, n.er, opts)
	}
}

// endpointDialFingerprint identifies the dialable surface of an endpoint
// record. Seq-only republishes (same endpoints/signals) share a fingerprint.
func endpointDialFingerprint(er *protocol.EndpointRecord) string {
	if er == nil {
		return ""
	}
	eps := append([]string(nil), er.Endpoints...)
	sigs := append([]string(nil), er.Signals...)
	if len(sigs) == 0 && er.Signal != "" {
		sigs = []string{er.Signal}
	}
	sort.Strings(eps)
	sort.Strings(sigs)
	return strings.Join(eps, "\n") + "|" + strings.Join(sigs, "\n")
}
