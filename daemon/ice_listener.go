// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"slices"
	"sync"
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

// incomingDedup tracks active ICE rooms across all signal hubs.
// When multiple hubs simultaneously deliver incoming for the same room,
// only the first one triggers AcceptICEViaSignal. The entry is released
// once AcceptICEViaSignal returns, so subsequent sessions for the same
// pair are never blocked.
type incomingDedup struct {
	mu   sync.Mutex
	seen map[string]struct{} // rooms currently being accepted
}

func newIncomingDedup() *incomingDedup {
	return &incomingDedup{seen: make(map[string]struct{})}
}

// tryMark returns true if room was not already in-flight (caller should proceed).
func (d *incomingDedup) tryMark(room string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[room]; ok {
		return false
	}
	d.seen[room] = struct{}{}
	return true
}

// release removes a room from the dedup set once AcceptICEViaSignal has
// finished, allowing new accept attempts for the same peer pair.
func (d *incomingDedup) release(room string) {
	d.mu.Lock()
	delete(d.seen, room)
	d.mu.Unlock()
}

// runICEListener manages per-hub /signal subscriptions. It monitors the
// effective signal URL list; when the list changes all active subscribers
// are cancelled and a new set is started. The shared incomingDedup prevents
// duplicate AcceptICEViaSignal calls when multiple hubs deliver the same
// incoming notification.
//
// d.iceRegNotify is broadcast to all active subscriber notify channels so
// that every hub re-sends reg frames immediately when agent registration changes.
func (d *Daemon) runICEListener(ctx context.Context) {
	var (
		notifyMu  sync.Mutex
		notifyChs []chan struct{} // one per active subscriber goroutine
	)

	// broadcast forwards iceRegNotify to all active subscriber goroutines.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.iceRegNotify:
				notifyMu.Lock()
				for _, ch := range notifyChs {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
				notifyMu.Unlock()
			}
		}
	}()

	seen := newIncomingDedup()

	var (
		lastURLs     []string
		workerCancel context.CancelFunc
		workerDone   <-chan struct{}
	)

	stopWorkers := func() {
		if workerCancel != nil {
			workerCancel()
			<-workerDone
			workerCancel = nil
			workerDone = nil
		}
		notifyMu.Lock()
		notifyChs = nil
		notifyMu.Unlock()
	}

	for ctx.Err() == nil {
		hasAgents := len(d.reg.List()) > 0
		urls := d.h.EffectiveICESignalURLs()

		if !hasAgents || len(urls) == 0 {
			stopWorkers()
			lastURLs = nil
			d.sleepICE(ctx, time.Second)
			continue
		}

		urlsChanged := !slices.Equal(urls, lastURLs)

		if urlsChanged {
			stopWorkers()
			lastURLs = slices.Clone(urls)

			workerCtx, cancel := context.WithCancel(ctx)
			workerCancel = cancel
			done := make(chan struct{})
			workerDone = done

			chs := make([]chan struct{}, len(urls))
			for i := range chs {
				chs[i] = make(chan struct{}, 1)
			}
			notifyMu.Lock()
			notifyChs = chs
			notifyMu.Unlock()

			var wg sync.WaitGroup
			for i, base := range urls {
				wg.Add(1)
				go func(base string, notify <-chan struct{}) {
					defer wg.Done()
					d.runSingleICESubscriber(workerCtx, base, seen, notify)
				}(base, chs[i])
			}
			go func() { wg.Wait(); close(done) }()
		}

		// Poll for URL / agent-list changes once per second.
		select {
		case <-ctx.Done():
			stopWorkers()
			return
		case <-time.After(time.Second):
		}
	}
	stopWorkers()
}

// runSingleICESubscriber maintains a persistent /signal WebSocket to one hub.
// It reconnects with exponential backoff on any connection failure.
// Incoming notifications are deduplicated via seen before spawning AcceptICEViaSignal.
func (d *Daemon) runSingleICESubscriber(ctx context.Context, base string, seen *incomingDedup, notify <-chan struct{}) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		subURL, err := signaling.SubscribeURL(base)
		if err != nil {
			d.log.Debug("ice listener subscribe url", "base", base, "err", err)
			d.sleepICE(ctx, backoff)
			backoff = nextICEBackoff(backoff)
			continue
		}
		conn, _, err := websocket.Dial(ctx, subURL, &websocket.DialOptions{
			Subprotocols: []string{signaling.SubprotocolICE},
		})
		if err != nil {
			d.log.Debug("ice listener dial", "base", base, "err", err)
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
			readErr <- d.readICELoopFor(ctx, conn, base, seen)
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
					d.log.Debug("ice listener keepalive", "base", base, "err", err)
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
					d.log.Debug("ice listener ping", "base", base, "err", pingErr)
					break outer
				}
			case <-notify:
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
					d.log.Debug("ice listener read", "base", base, "err", err)
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

// readICELoopFor reads incoming frames from a /signal connection and dispatches
// AcceptICEViaSignal for each new ICE session. base is the hub that sent the
// incoming frame; the callee must join the same hub's /ice room as the caller.
// seen deduplicates across hubs so only one goroutine accepts per session.
func (d *Daemon) readICELoopFor(ctx context.Context, conn *websocket.Conn, base string, seen *incomingDedup) error {
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
		// Compute room locally (same formula as caller) rather than trusting
		// fr.Room from the hub, which may be absent in non-conformant servers.
		// Dedup: only the first hub to deliver incoming for this room triggers Accept.
		room := signaling.RoomID(localAgent.String(), callerAID.String())
		if !seen.tryMark(room) {
			d.log.Debug("ice incoming dedup", "base", base, "room", room)
			continue
		}
		go func() {
			// Release the dedup entry when Accept finishes (success or failure)
			// so that a subsequent session for the same peer pair is never blocked.
			defer seen.release(room)
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
