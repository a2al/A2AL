// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

const envelopeRPCTimeout = 5 * time.Second

// EnvelopePersisted is the SendEnvelope API result when the envelope was stored
// via mailbox. It is never written on the a2en wire.
const EnvelopePersisted uint8 = 0

var errEnvelopeUnavailable = errors.New("a2al/daemon: no live envelope stream")

// EnvelopeResult is the coarse outcome of SendEnvelope or a consumer.
type EnvelopeResult struct {
	Code  uint8
	Extra []byte
}

// EnvelopeConsumer handles one kind. consumed=true means this is not an
// ordinary mailbox note (no mailbox.received, not pending.mailbox).
type EnvelopeConsumer func(local, remote a2al.Address, kind string, body []byte) (consumed bool, result EnvelopeResult)

// RegisterEnvelopeConsumer installs fn for kind. fn=nil removes the entry.
func (d *Daemon) RegisterEnvelopeConsumer(kind string, fn EnvelopeConsumer) {
	if kind == "" {
		return
	}
	if fn == nil {
		d.envConsumers.delete(kind)
		return
	}
	d.envConsumers.put(kind, fn)
}

func (d *Daemon) hasEnvelopeConsumers() bool {
	return d.envConsumers.len() > 0
}

func (d *Daemon) consumeEnvelope(local, remote a2al.Address, kind string, body []byte) (bool, EnvelopeResult) {
	fn := d.envConsumers.get(kind)
	if fn == nil {
		return false, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	return fn(local, remote, kind, body)
}

func (d *Daemon) dispatchEnvelope(local, remote a2al.Address, kind string, body []byte) EnvelopeResult {
	_, res := d.consumeEnvelope(local, remote, kind, body)
	if res.Code == 0 {
		res.Code = protocol.EnvelopeDenied
	}
	res.Code = protocol.NormalizeEnvelopeCode(res.Code)
	return res
}

// SendEnvelope delivers kind+body on a live a2en stream when one exists.
// persist stores MailboxMsgEnvelope via execMailboxSend only when no coarse
// result was read. persist never reports EnvelopeOK.
func (d *Daemon) SendEnvelope(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
	inner, err := protocol.EncodeEnvelopeInner(kind, body)
	if err != nil {
		return EnvelopeResult{}, err
	}
	d.regMu.RLock()
	e := d.reg.Get(local)
	d.regMu.RUnlock()
	if e == nil && local != d.nodeAddr {
		return EnvelopeResult{}, errNotFound
	}
	d.touchHeartbeat(local)

	if conn := d.liveEnvelopeConn(local, remote); conn != nil {
		res, err := sendEnvelopeOn(ctx, conn, kind, body)
		if err == nil {
			return res, nil
		}
		var oe *errOpenStream
		if errors.As(err, &oe) && d.connPool != nil && (ctx.Err() == nil || conn.Context().Err() != nil) {
			d.connPool.evictUnheld(conn)
		}
	}
	if persist {
		if _, err := d.execMailboxSend(ctx, local.String(), remote.String(), protocol.MailboxMsgEnvelope, inner); err != nil {
			return EnvelopeResult{}, err
		}
		return EnvelopeResult{Code: EnvelopePersisted}, nil
	}
	return EnvelopeResult{}, errEnvelopeUnavailable
}

func (d *Daemon) liveEnvelopeConn(local, remote a2al.Address) quic.Connection {
	if d.connPool == nil || d.h == nil {
		return nil
	}
	conn := d.connPool.getLive(local, remote)
	if conn == nil || !d.h.PeerEnvelopeStream(conn) {
		return nil
	}
	return conn
}

func sendEnvelopeOn(ctx context.Context, conn quic.Connection, kind string, body []byte) (EnvelopeResult, error) {
	sendCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		sendCtx, cancel = context.WithTimeout(ctx, envelopeRPCTimeout)
	}
	defer cancel()

	str, err := openLimited(sendCtx, conn, func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		return c.OpenStreamSync(ctx)
	})
	if err != nil {
		return EnvelopeResult{}, &errOpenStream{err}
	}
	defer str.Close()
	if dl, ok := sendCtx.Deadline(); ok {
		_ = str.SetDeadline(dl)
	}
	if err := protocol.WriteEnvelopeFrame(str, kind, body); err != nil {
		return EnvelopeResult{}, err
	}
	code, extra, err := protocol.ReadEnvelopeResult(str)
	if err != nil {
		return EnvelopeResult{}, err
	}
	return EnvelopeResult{Code: code, Extra: extra}, nil
}

func (d *Daemon) acceptEnvelope(ac *host.AgentConn, str quic.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(envelopeRPCTimeout))
	if !d.decideAccess(ac.Local, ac.Remote, "", ac.RemoteAddr(), accessEnvelope) {
		_ = protocol.WriteEnvelopeResult(str, protocol.EnvelopeDenied, nil)
		return
	}
	kind, body, err := protocol.ReadEnvelopeFrameBody(str)
	if err != nil {
		_ = protocol.WriteEnvelopeResult(str, protocol.EnvelopeDenied, nil)
		return
	}
	res := d.dispatchEnvelope(ac.Local, ac.Remote, kind, body)
	if err := protocol.WriteEnvelopeResult(str, res.Code, res.Extra); err != nil {
		d.log.Debug("envelope: write result", "err", err)
	}
}
