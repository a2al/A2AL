// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/chat"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

func envelopeSignalingOK(res EnvelopeResult, err error) bool {
	if err != nil {
		return false
	}
	switch res.Code {
	case protocol.EnvelopeOK, protocol.EnvelopePending, EnvelopePersisted:
		return true
	default:
		return false
	}
}

func signalingErr(res EnvelopeResult, err error) error {
	if envelopeSignalingOK(res, err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", chat.ErrSignaling, err)
	}
	switch res.Code {
	case protocol.EnvelopePowRequired:
		n := 0
		if len(res.Extra) > 0 {
			n = int(res.Extra[0])
		}
		return fmt.Errorf("%w: pow_required bits=%d", chat.ErrSignaling, n)
	case protocol.EnvelopeRetryLater:
		return fmt.Errorf("%w: retry_later", chat.ErrSignaling)
	default:
		return fmt.Errorf("%w: denied", chat.ErrSignaling)
	}
}

func (d *Daemon) chatDeliver(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
	if d.chatDeliverHook != nil {
		return d.chatDeliverHook(ctx, local, remote, kind, body, persist)
	}
	return d.chatDeliverReal(ctx, local, remote, kind, body, persist)
}

func (d *Daemon) chatDeliverReal(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
	if local == remote {
		return EnvelopeResult{}, chat.ErrSelf
	}
	d.touchHeartbeat(local)
	if d.isLocalAID(remote) {
		_, res := d.consumeEnvelope(remote, local, kind, body)
		if res.Code == 0 {
			res.Code = protocol.EnvelopeDenied
		}
		res.Code = protocol.NormalizeEnvelopeCode(res.Code)
		return res, nil
	}
	conn, dialErr := d.chatDial(ctx, local, remote)
	if conn != nil {
		res, err := sendEnvelopeOn(ctx, conn, kind, body)
		if err == nil {
			return res, nil
		}
		var oe *errOpenStream
		drop := errors.As(err, &oe) && d.connPool != nil && (ctx.Err() == nil || conn.Context().Err() != nil)
		if drop && d.connPool.evictUnheld(conn) && ctx.Err() == nil {
			conn2, err2 := d.chatDialRepair(ctx, local, remote)
			if conn2 != nil {
				res, err = sendEnvelopeOn(ctx, conn2, kind, body)
				if err == nil {
					return res, nil
				}
				var oe2 *errOpenStream
				if errors.As(err, &oe2) && (ctx.Err() == nil || conn2.Context().Err() != nil) {
					d.connPool.evictUnheld(conn2)
				}
			}
			if err2 != nil {
				dialErr = err2
			} else {
				dialErr = err
			}
		} else {
			dialErr = err
		}
	}
	if persist {
		return d.chatPersist(ctx, local, remote, kind, body)
	}
	if dialErr != nil {
		return EnvelopeResult{}, dialErr
	}
	return EnvelopeResult{}, errEnvelopeUnavailable
}

// chatDial reuses a live outbound QUIC conn, otherwise waits on acquire.
// Same-daemon AIDs are handled by chatDeliverReal before this is called.
func (d *Daemon) chatDial(ctx context.Context, local, remote a2al.Address) (quic.Connection, error) {
	if d.connPool == nil {
		return nil, errEnvelopeUnavailable
	}
	if conn := d.connPool.getLive(local, remote); conn != nil {
		return conn, nil
	}
	var er *protocol.EndpointRecord
	if d.h != nil && d.h.Node() != nil {
		rec, _, err := d.resolveTracked(ctx, remote)
		if err != nil {
			return nil, err
		}
		er = rec
	}
	if er == nil {
		return nil, errEnvelopeUnavailable
	}
	conn, _, err := d.connPool.acquire(ctx, local, remote, er, false, true)
	return conn, err
}

// chatDialRepair replaces a connection that just failed to open a stream.
// The wait is capped; a slow dial may still complete into the pool afterwards.
func (d *Daemon) chatDialRepair(ctx context.Context, local, remote a2al.Address) (quic.Connection, error) {
	if d.connPool == nil {
		return nil, errEnvelopeUnavailable
	}
	var er *protocol.EndpointRecord
	if d.h != nil && d.h.Node() != nil {
		rec, _, err := d.resolveTracked(ctx, remote)
		if err != nil {
			return nil, err
		}
		er = rec
	}
	if er == nil {
		return nil, errEnvelopeUnavailable
	}
	conn, _, err := d.connPool.acquireRepair(ctx, local, remote, er, false, true)
	return conn, err
}

func (d *Daemon) chatPersist(ctx context.Context, local, remote a2al.Address, kind string, body []byte) (EnvelopeResult, error) {
	inner, err := protocol.EncodeEnvelopeInner(kind, body)
	if err != nil {
		return EnvelopeResult{}, err
	}
	if _, err := d.execMailboxSend(ctx, local.String(), remote.String(), protocol.MailboxMsgEnvelope, inner); err != nil {
		return EnvelopeResult{}, err
	}
	return EnvelopeResult{Code: EnvelopePersisted}, nil
}

func (d *Daemon) enqueueChatWake(local, remote a2al.Address, sendPull bool) {
	if d.chats == nil {
		return
	}
	key := local.String() + "|" + remote.String()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		_, _, _ = d.chats.flight.Do(key, func() (any, error) {
			d.chatWake(ctx, local, remote, sendPull)
			return nil, nil
		})
	}()
}

// enqueueChatHeal replies with accept then flushes. Used when an inbound
// invite means both sides already wanted the link (we were out_pending or
// already mutual). Accept is sent first so chat.msg is not denied on the peer.
func (d *Daemon) enqueueChatHeal(local, remote a2al.Address) {
	if d.chats == nil {
		return
	}
	key := "heal|" + local.String() + "|" + remote.String()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		_, _, _ = d.chats.flight.Do(key, func() (any, error) {
			_, _ = d.chatDeliver(ctx, local, remote, chat.KindAccept, chat.EncodeEmpty(), true)
			d.chatFlush(ctx, local, remote)
			return nil, nil
		})
	}()
}

func (d *Daemon) chatWake(ctx context.Context, local, remote a2al.Address, sendPull bool) {
	d.chatFlush(ctx, local, remote)
	if sendPull {
		after := uint64(0)
		if st, err := d.chatStore(local); err == nil {
			after = st.MaxInSeq(remote)
		}
		body, err := chat.EncodePull(after)
		if err != nil {
			return
		}
		_, _ = d.chatDeliver(ctx, local, remote, chat.KindPull, body, true)
	}
}

func (d *Daemon) chatFlush(ctx context.Context, local, remote a2al.Address) {
	d.flushChatUnsent(ctx, local, remote, false)
}

// settleChatUnsent is the pathLive settler: only the live pooled conn, never acquire.
func (d *Daemon) settleChatUnsent(ctx context.Context, local, remote a2al.Address) {
	if d.connPool == nil || d.connPool.getLive(local, remote) == nil {
		return
	}
	d.flushChatUnsent(ctx, local, remote, true)
}

func (d *Daemon) flushChatUnsent(ctx context.Context, local, remote a2al.Address, liveOnly bool) {
	st, err := d.chatStore(local)
	if err != nil {
		return
	}
	e, ok := st.Get(remote)
	if !ok || e.State != chat.StateMutual {
		return
	}
	for _, rec := range st.Unsent(remote) {
		body, err := chat.EncodeMsg(chat.MsgFromRec(rec))
		if err != nil {
			continue
		}
		var res EnvelopeResult
		if liveOnly {
			res, err = d.sendChatUnsentLive(ctx, local, remote, body)
		} else {
			res, err = d.chatDeliver(ctx, local, remote, chat.KindMsg, body, false)
		}
		if err == nil && res.Code == protocol.EnvelopeOK {
			_ = st.MarkSent(remote, rec.Seq)
			continue
		}
		return
	}
}

func (d *Daemon) sendChatUnsentLive(ctx context.Context, local, remote a2al.Address, body []byte) (EnvelopeResult, error) {
	if d.chatDeliverHook != nil {
		return d.chatDeliverHook(ctx, local, remote, chat.KindMsg, body, false)
	}
	if d.connPool == nil {
		return EnvelopeResult{}, errEnvelopeUnavailable
	}
	conn := d.connPool.getLive(local, remote)
	if conn == nil {
		return EnvelopeResult{}, errEnvelopeUnavailable
	}
	return sendEnvelopeOn(ctx, conn, chat.KindMsg, body)
}

func (d *Daemon) chatDing(ctx context.Context, local, remote a2al.Address) {
	st, err := d.chatStore(local)
	if err != nil {
		return
	}
	if st.DingFresh(remote) {
		return
	}
	res, err := d.chatDeliver(ctx, local, remote, chat.KindDing, chat.EncodeEmpty(), true)
	if err != nil {
		return
	}
	if res.Code == protocol.EnvelopeOK || res.Code == EnvelopePersisted || res.Code == protocol.EnvelopePending {
		_ = st.TouchDing(remote)
	}
}
