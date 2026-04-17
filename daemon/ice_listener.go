// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"time"

	"github.com/a2al/a2al"
	"github.com/coder/websocket"

	"github.com/a2al/a2al/signaling"
)

// iceKeepaliveInterval is how often the daemon re-sends reg frames on an idle
// /signal connection. Re-sending reg frames (application-layer data frames)
// resets the server-side 60 s read deadline and traverses any intermediate
// proxy idle timeouts (typically 90 s). 45 s satisfies both constraints with
// comfortable margin and reduces ping frequency vs the original 30 s spec.
const iceKeepaliveInterval = 45 * time.Second

// runICEListener maintains a WebSocket subscription to /signal and spawns
// AcceptICEViaSignal when the hub notifies this node of an inbound ICE session.
func (d *Daemon) runICEListener(ctx context.Context) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		base := d.h.EffectiveICESignalBase()
		if base == "" || len(d.reg.List()) == 0 {
			d.sleepICE(ctx, time.Second)
			backoff = 2 * time.Second
			continue
		}
		subURL, err := signaling.SubscribeURL(base)
		if err != nil {
			d.log.Debug("ice listener subscribe url", "err", err)
			d.sleepICE(ctx, backoff)
			backoff = nextICEBackoff(backoff)
			continue
		}
		conn, _, err := websocket.Dial(ctx, subURL, &websocket.DialOptions{
			Subprotocols: []string{signaling.SubprotocolICE},
		})
		if err != nil {
			d.log.Debug("ice listener dial", "err", err)
			d.sleepICE(ctx, backoff)
			backoff = nextICEBackoff(backoff)
			continue
		}
		backoff = 2 * time.Second
		if err := d.sendICERegs(ctx, conn); err != nil {
			_ = conn.CloseNow()
			d.sleepICE(ctx, backoff)
			continue
		}
		readErr := make(chan error, 1)
		go func() {
			readErr <- d.readICELoop(ctx, conn)
		}()
		keepalive := time.NewTicker(iceKeepaliveInterval)
	outer:
		for {
			select {
			case <-ctx.Done():
				keepalive.Stop()
				_ = conn.CloseNow()
				<-readErr
				return
			case <-keepalive.C:
				// Re-send reg frames to reset the server-side read deadline and
				// keep intermediate proxies alive, then Ping to confirm the server
				// is reachable (pong is processed by the concurrent Read goroutine).
				if err := d.sendICERegs(ctx, conn); err != nil {
					keepalive.Stop()
					_ = conn.CloseNow()
					if ctx.Err() != nil {
						<-readErr
						return
					}
					d.log.Debug("ice listener keepalive", "err", err)
					break outer
				}
				pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
				pingErr := conn.Ping(pctx)
				pcancel()
				if pingErr != nil {
					keepalive.Stop()
					_ = conn.CloseNow()
					if ctx.Err() != nil {
						<-readErr
						return
					}
					d.log.Debug("ice listener ping", "err", pingErr)
					break outer
				}
			case <-d.iceRegNotify:
				if err := d.sendICERegs(ctx, conn); err != nil {
					keepalive.Stop()
					_ = conn.CloseNow()
					break outer
				}
			case err := <-readErr:
				keepalive.Stop()
				_ = conn.CloseNow()
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					d.log.Debug("ice listener read", "err", err)
				}
				break outer
			}
		}
		d.sleepICE(ctx, backoff)
		backoff = nextICEBackoff(backoff)
	}
}

func nextICEBackoff(b time.Duration) time.Duration {
	if b < 60*time.Second {
		return b * 2
	}
	return b
}

func (d *Daemon) sleepICE(ctx context.Context, dura time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(dura):
	}
}

func (d *Daemon) sendICERegs(ctx context.Context, conn *websocket.Conn) error {
	for _, e := range d.reg.List() {
		b, err := signaling.EncodeFrame(signaling.Frame{T: "reg", AID: e.AID.String()})
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = conn.Write(wctx, websocket.MessageBinary, b)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) readICELoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		// No per-read deadline: keepalive sends reg frames every 45 s and Pings
		// the server to confirm liveness. Dead connections are detected via Ping
		// timeout rather than a read timeout, eliminating spurious reconnects.
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		fr, err := signaling.DecodeFrame(data)
		if err != nil {
			continue
		}
		if fr.T != "incoming" || fr.Caller == "" || fr.Target == "" {
			continue
		}
		localAgent, err := a2al.ParseAddress(fr.Target)
		if err != nil {
			continue
		}
		callerAID, err := a2al.ParseAddress(fr.Caller)
		if err != nil {
			continue
		}
		base := d.h.EffectiveICESignalBase()
		if base == "" {
			continue
		}
		go func() {
			actx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			ac, err := d.h.AcceptICEViaSignal(actx, localAgent, callerAID, base)
			cancel() // handshake established (or failed); no longer need startup timeout context.
			if err != nil {
				d.log.Debug("ice accept", "err", err, "local", localAgent.String(), "remote", callerAID.String())
				return
			}
			if !d.tryAcquireGatewayConn() {
				d.log.Warn("gateway: max connections reached", "limit", maxGatewayConns)
				_ = ac.CloseWithError(1, "too many connections")
				return
			}
			defer d.releaseGatewayConn()
			d.log.Debug("ice gateway: quic accepted", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
			d.serveGatewayConn(ctx, ac)
		}()
	}
}

func (d *Daemon) bumpIceRegistry() {
	if d.iceRegNotify == nil {
		return
	}
	select {
	case d.iceRegNotify <- struct{}{}:
	default:
	}
}
