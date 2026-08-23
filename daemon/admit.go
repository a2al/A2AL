// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"

	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

func (d *Daemon) openAdmittedStream(ctx context.Context, conn quic.Connection, token string) (quic.Stream, error) {
	if d.h.PeerServiceStream(conn) {
		return host.AdmitServiceStream(ctx, conn, token)
	}
	return conn.OpenStreamSync(ctx)
}

// probeServiceAdmission returns whether the peer allows a service stream now.
// Old peers (no a2s1) are treated as allowed at this layer.
func (d *Daemon) probeServiceAdmission(ctx context.Context, conn quic.Connection, token string) (bool, error) {
	if !d.h.PeerServiceStream(conn) {
		return true, nil
	}
	str, err := host.AdmitServiceStream(ctx, conn, token)
	if err != nil {
		if isAccessDeniedErr(err) {
			return false, nil
		}
		return false, err
	}
	_ = str.Close()
	return true, nil
}
