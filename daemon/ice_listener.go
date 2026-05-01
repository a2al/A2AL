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

const (
	// signalSlots is the target number of simultaneously connected signal hubs.
	signalSlots = 2
	// signalNeverRetries is the number of consecutive dial failures allowed for
	// a hub that has never connected before it is put into cooldown.
	signalNeverRetries = 3
	// signalNeverDelay is the pause between attempts for a never-connected hub.
	signalNeverDelay = 5 * time.Second
	// signalQuickRetries is the number of reconnect attempts allowed after a
	// previously live hub disconnects unexpectedly.
	signalQuickRetries = 3
	// signalQuickDelay is the pause between quick reconnect attempts.
	signalQuickDelay = 2 * time.Second
	// signalCooldown is how long a hub stays out of rotation after exhausting
	// its never-connected retries.
	signalCooldown = 5 * time.Minute
)

// signalSlotState is the shared pool managed by runICEListener. It tracks
// which candidate URLs are claimed (being attempted by a slot), active
// (connected), or in cooldown (temporarily excluded).
type signalSlotState struct {
	d    *Daemon
	mu   sync.Mutex
	act  map[string]struct{}   // currently connected hubs
	clm  map[string]struct{}   // hubs being attempted (not yet connected)
	cool map[string]time.Time  // hubs excluded until this time
}

func newSignalSlotState(d *Daemon) *signalSlotState {
	return &signalSlotState{
		d:    d,
		act:  make(map[string]struct{}),
		clm:  make(map[string]struct{}),
		cool: make(map[string]time.Time),
	}
}

// pick selects and claims the first available candidate not already active,
// claimed, or in cooldown. Returns "" if no candidate is available right now.
func (s *signalSlotState) pick(candidates []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, u := range candidates {
		if _, ok := s.act[u]; ok {
			continue
		}
		if _, ok := s.clm[u]; ok {
			continue
		}
		if t, ok := s.cool[u]; ok && now.Before(t) {
			continue
		}
		s.clm[u] = struct{}{}
		return u
	}
	return ""
}

// markConnected transitions url from claimed → active and notifies the host.
func (s *signalSlotState) markConnected(url string) {
	s.mu.Lock()
	delete(s.clm, url)
	s.act[url] = struct{}{}
	delete(s.cool, url)
	s.mu.Unlock()
	s.flush()
}

// markCooldown puts a never-connected url into cooldown and releases its claim.
func (s *signalSlotState) markCooldown(url string) {
	s.mu.Lock()
	delete(s.clm, url)
	s.cool[url] = time.Now().Add(signalCooldown)
	s.mu.Unlock()
}

// release removes url from both claimed and active sets and notifies the host.
// Safe to call more than once (idempotent map deletes).
func (s *signalSlotState) release(url string) {
	s.mu.Lock()
	delete(s.clm, url)
	delete(s.act, url)
	s.mu.Unlock()
	s.flush()
}

// flush snapshots the active set and pushes it to the host for DHT publishing.
func (s *signalSlotState) flush() {
	s.mu.Lock()
	urls := make([]string, 0, len(s.act))
	for u := range s.act {
		urls = append(urls, u)
	}
	s.mu.Unlock()
	slices.Sort(urls)
	s.d.h.SetActiveSignalURLs(urls)
}

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

// runICEListener manages signalSlots concurrent hub connections. Each slot
// independently picks from the candidate list, attempts to connect, and reports
// its live state through signalSlotState. d.iceRegNotify is broadcast to all
// active slots so every hub re-sends reg frames on agent registration changes.
func (d *Daemon) runICEListener(ctx context.Context) {
	seen := newIncomingDedup()
	state := newSignalSlotState(d)

	// Per-slot notify channels; broadcast goroutine fans out from d.iceRegNotify.
	notifyChs := make([]chan struct{}, signalSlots)
	for i := range notifyChs {
		notifyChs[i] = make(chan struct{}, 1)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.iceRegNotify:
				for _, ch := range notifyChs {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < signalSlots; i++ {
		wg.Add(1)
		notify := notifyChs[i]
		go func() {
			defer wg.Done()
			d.runSignalSlot(ctx, state, seen, notify)
		}()
	}
	wg.Wait()
}

// runSignalSlot is one connection slot in the signal pool. It repeatedly picks
// an available hub candidate and calls runSignalURL until the context is done.
func (d *Daemon) runSignalSlot(ctx context.Context, state *signalSlotState, seen *incomingDedup, notify <-chan struct{}) {
	for ctx.Err() == nil {
		url := state.pick(d.h.EffectiveICESignalURLs())
		if url == "" {
			d.sleepICE(ctx, 5*time.Second)
			continue
		}
		d.runSignalURL(ctx, url, state, seen, notify)
	}
}

// runSignalURL manages the full lifecycle of one hub URL for a slot: initial
// connection attempts, keepalive, and reconnect after disconnection.
// If the hub never connects within signalNeverRetries attempts it is cooled down;
// if it loses an established connection the slot tries signalQuickRetries times
// before releasing the URL and returning (slot picks a new one).
func (d *Daemon) runSignalURL(ctx context.Context, url string, state *signalSlotState, seen *incomingDedup, notify <-chan struct{}) {
	// release covers all exit paths; markCooldown also clears the claim so the
	// extra delete on already-absent map keys is harmless (idempotent).
	defer state.release(url)

	wasConnected := false
	fails := 0

	for ctx.Err() == nil {
		conn, err := d.connectHub(ctx, url)
		if err != nil {
			fails++
			if !wasConnected {
				if fails >= signalNeverRetries {
					d.log.Debug("ice hub unreachable, cooling down", "base", url)
					state.markCooldown(url)
					return
				}
				d.sleepICE(ctx, signalNeverDelay)
			} else {
				if fails >= signalQuickRetries {
					d.log.Debug("ice hub reconnect failed, releasing", "base", url)
					return
				}
				d.sleepICE(ctx, signalQuickDelay)
			}
			continue
		}

		if !wasConnected {
			state.markConnected(url)
			wasConnected = true
		}
		fails = 0

		d.runHubSession(ctx, conn, url, seen, notify)
		// Disconnected; loop to reconnect.
	}
}

// connectHub dials a signal hub and sends initial reg frames.
// Both steps are treated atomically: a failed sendICERegs closes the connection.
func (d *Daemon) connectHub(ctx context.Context, base string) (*websocket.Conn, error) {
	subURL, err := signaling.SubscribeURL(base)
	if err != nil {
		return nil, err
	}
	conn, _, err := websocket.Dial(ctx, subURL, &websocket.DialOptions{
		Subprotocols: []string{signaling.SubprotocolICE},
	})
	if err != nil {
		return nil, err
	}
	if err := d.sendICERegs(ctx, conn); err != nil {
		_ = conn.CloseNow()
		return nil, err
	}
	return conn, nil
}

// runHubSession runs the keepalive loop for an established hub connection.
// It returns when the connection is lost or ctx is cancelled.
func (d *Daemon) runHubSession(ctx context.Context, conn *websocket.Conn, base string, seen *incomingDedup, notify <-chan struct{}) {
	readErr := make(chan error, 1)
	go func() { readErr <- d.readICELoopFor(ctx, conn, base, seen) }()

	keepalive := time.NewTicker(iceKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = conn.CloseNow()
			<-readErr
			return
		case <-keepalive.C:
			// Re-send reg frames to reset the server-side read deadline and keep
			// intermediate proxies alive, then Ping to confirm end-to-end liveness.
			if err := d.sendICERegs(ctx, conn); err != nil {
				_ = conn.CloseNow()
				if ctx.Err() != nil {
					<-readErr
					return
				}
				d.log.Debug("ice keepalive", "base", base, "err", err)
				<-readErr
				return
			}
			pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			pingErr := conn.Ping(pctx)
			pcancel()
			if pingErr != nil {
				_ = conn.CloseNow()
				if ctx.Err() != nil {
					<-readErr
					return
				}
				d.log.Debug("ice ping", "base", base, "err", pingErr)
				<-readErr
				return
			}
		case <-notify:
			if err := d.sendICERegs(ctx, conn); err != nil {
				_ = conn.CloseNow()
				<-readErr
				return
			}
		case err := <-readErr:
			_ = conn.CloseNow()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				d.log.Debug("ice read", "base", base, "err", err)
			}
			return
		}
	}
}

func (d *Daemon) sleepICE(ctx context.Context, dura time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(dura):
	}
}

func (d *Daemon) sendICERegs(ctx context.Context, conn *websocket.Conn) error {
	// Collect all identities to register: node identity first (enables DHT hole-punching
	// callee), then each user agent (enables Mode A application connections).
	aids := make([]string, 0, 1+len(d.reg.List()))
	aids = append(aids, d.nodeAddr.String())
	for _, e := range d.reg.List() {
		aids = append(aids, e.AID.String())
	}
	for _, aid := range aids {
		b, err := signaling.EncodeFrame(signaling.Frame{T: "reg", AID: aid})
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

		if localAgent == d.nodeAddr {
			// Mode B: caller is another DHT node punching this node's control plane.
			// Hand off to DHTpunchPool without an agent-route handshake.
			callerNodeID := a2al.NodeIDFromAddress(callerAID)
			go func() {
				defer seen.release(room)
				actx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				d.h.DHTpunchPool().HandleIncomingPunch(actx, callerNodeID, callerAID, base, room)
			}()
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
