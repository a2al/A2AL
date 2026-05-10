// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

// DCUtR-style synchronized hole punching.
//
// Protocol (over the existing ICE signaling WebSocket):
//
//	Caller  ──punch-init{addrs,ts}──►  Callee   (srflx exchange + RTT seed)
//	Caller  ◄─punch-ack{addrs,ts}──    Callee   (ts echoed for RTT)
//
//	Per round (up to punchMaxRounds):
//	  Caller  ──punch-go──────────────►  Callee
//	  Caller waits RTT/2 then fires;     Callee fires immediately on receipt.
//
// No absolute clock synchronization is required. The one-way delay estimate
// (RTT/2) aligns both sides to ±RTT/2, which is acceptable for CGNAT.
//
// Single-socket design: both the outgoing QUIC dials and the incoming
// accept use the host's main quicTr/qListen (port 4121). This ensures a
// stable NAT mapping – the same mapping the peer already knows from the
// DHT endpoint record. Incoming punch connections are routed via the
// punchExpect sync.Map populated in host.go Accept().

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/natsense"
	"github.com/a2al/a2al/signaling"
)

const (
	// punchHandshakeTimeout caps the punch-init → punch-ack exchange.
	punchHandshakeTimeout = 8 * time.Second

	// punchFireTimeout is the per-round window for QUIC dial/accept.
	// Kept intentionally tight so two rounds fit well within the ICE timeout.
	punchFireTimeout = 2500 * time.Millisecond

	// punchRetryDelay is the pause between rounds. Brief enough that the CGNAT
	// mapping from round 1 is still alive when round 2 fires.
	punchRetryDelay = 1500 * time.Millisecond

	// punchMaxRounds is the number of fire attempts per punchDial call.
	punchMaxRounds = 2

	// punchGoWaitTimeout is the per-round callee timeout for receiving punch-go.
	// Must cover: caller's retry delay + caller's fire timeout + margin.
	punchGoWaitTimeout = punchRetryDelay + punchFireTimeout + 2*time.Second

	// punchSymmetricSpread is the ±port range sprayed when the remote is detected
	// as a Symmetric NAT (two punch-init addresses have different external ports).
	// Spraying opens the local Port-Restricted NAT for the range of ports the
	// remote's Symmetric NAT is likely to allocate when firing back at us.
	punchSymmetricSpread = 5
)

// punchLocalAddrs returns the external address(es) of the host's QUIC socket
// (port 4121) for use in the punch-init/ack handshake.
//
// Sources (all that apply are returned, deduplicated):
//  1. natsense TrustedUDP consensus — the NAT-mapped external port of the
//     4121 socket as observed by DHT peers. May reflect a Symmetric mapping
//     useless to other peers, so it's offered alongside other candidates.
//  2. UPnP-mapped address — when active, this is a static port-forward that
//     ANY peer can reach regardless of our outbound NAT behavior. Critical
//     for Symmetric NAT nodes that otherwise cannot accept inbound from peers.
//  3. extipSnap IP + local QUIC port — fallback for port-preserving NATs
//     when natsense is not yet ready.
//
// Returns nil if no external address can be determined.
func (h *Host) punchLocalAddrs() []string {
	localPort := h.QUICLocalAddr().Port
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// ① natsense observed external port for the QUIC socket.
	if host, natPort, ok := h.sense.TrustedUDP(); ok && net.ParseIP(host) != nil {
		port := int(natPort)
		if port == 0 {
			port = localPort
		}
		add(net.JoinHostPort(host, strconv.Itoa(port)))
	}

	// ② UPnP-mapped address (any peer can reach via static port-forward).
	h.upnpMu.Lock()
	upnpURL := h.upnpURL
	h.upnpMu.Unlock()
	if upnpURL != "" {
		if u, err := url.Parse(upnpURL); err == nil && u.Host != "" {
			add(u.Host)
		}
	}

	// ③ Fallback: extipSnap IP + local QUIC port (port-preserving NATs).
	if len(out) == 0 {
		h.extipMu.Lock()
		snap := h.extipSnap
		h.extipMu.Unlock()
		if snap != "" {
			ipStr := snap
			if ip, _, err := net.SplitHostPort(snap); err == nil {
				ipStr = ip
			}
			add(net.JoinHostPort(ipStr, strconv.Itoa(localPort)))
		}
	}
	return out
}

// expandSymmetricPunch returns the primary srflx address plus its ±spread port
// neighbours (same IP). The primary address is always first. Used when the
// remote is a Symmetric NAT to probe the likely actual outgoing port it will
// use when its NAT creates a fresh mapping toward us.
func expandSymmetricPunch(primary string, spread int) []string {
	base, err := net.ResolveUDPAddr("udp4", primary)
	if err != nil || base == nil {
		return []string{primary}
	}
	out := make([]string, 0, 1+2*spread)
	out = append(out, primary)
	ipStr := base.IP.String()
	for d := 1; d <= spread; d++ {
		if p := base.Port - d; p > 0 {
			out = append(out, fmt.Sprintf("%s:%d", ipStr, p))
		}
		if p := base.Port + d; p <= 65535 {
			out = append(out, fmt.Sprintf("%s:%d", ipStr, p))
		}
	}
	return out
}

// punchWin is an established QUIC connection produced by a punch fire round.
// teardown must be called exactly once when the connection is no longer needed.
type punchWin struct {
	qc       quic.Connection
	peer     *net.UDPAddr
	teardown func()
}

// punchDial runs the DCUtR hole-punch protocol over sess's signaling WebSocket.
//
// Phase 1 – address exchange (punch-init/ack): establishes the remote's punch
// srflx list and measures RTT between the two sides.
//
// Phase 2 – fire rounds (up to punchMaxRounds): each round the caller sends
// punch-go and waits RTT/2; the callee fires immediately on receipt. Both sides
// simultaneously listen for incoming QUIC (via h.qListen / punchExpect) and
// dial to the peer's punch srflx using the host's main quicTr. The stable
// NAT mapping of port 4121 is reused across rounds.
//
// All established QUIC connections are delivered to outCh as they arrive.
// outCh is closed when no more connections are expected (all rounds finished or
// ctx cancelled). The caller must drain outCh fully; each received punchWin's
// teardown must be called when the connection is no longer needed.
// punchDial returns a non-nil error only if setup (address / handshake) fails.
func (h *Host) punchDial(
	ctx context.Context,
	sess *iceSession,
	controlling bool,
	localCert tls.Certificate,
	expectRemote a2al.Address,
	qcfg *quic.Config,
	outCh chan<- punchWin,
) error {
	if expectRemote == (a2al.Address{}) {
		return fmt.Errorf("punch: expectRemote not set")
	}

	localAddrs := h.punchLocalAddrs()
	if len(localAddrs) == 0 {
		return fmt.Errorf("punch: cannot determine external QUIC address (natsense not ready)")
	}
	localNat := h.sense.InferNATType()
	// Probe-based FullCone classification can be misleading when UPnP makes the
	// 4121 port externally reachable while outbound NAT is actually Symmetric.
	// If natsense has any live evidence of multiple distinct external ports,
	// downgrade to Symmetric so the peer applies port-spray on its fire round.
	if localNat == natsense.NATFullCone && h.sense.HasMultiPortEvidence() {
		localNat = natsense.NATSymmetric
	}
	h.log.Debug("punch: local addrs", "component", "punch",
		"controlling", controlling, "addrs", localAddrs, "nat", localNat)

	// --- Phase 1: address exchange ---
	hsCtx, hsCancel := context.WithTimeout(ctx, punchHandshakeTimeout)
	defer hsCancel()

	var remoteSrflxes []string
	var remoteNat uint8
	var rttMs int64
	var hsErr error

	if controlling {
		remoteSrflxes, remoteNat, rttMs, hsErr = punchCallerHandshake(hsCtx, sess, localAddrs, localNat)
	} else {
		remoteSrflxes, remoteNat, hsErr = punchCalleeHandshake(hsCtx, sess, localAddrs, localNat)
	}
	if hsErr != nil {
		h.log.Debug("punch: handshake failed", "component", "punch",
			"controlling", controlling, "err", hsErr)
		return fmt.Errorf("punch handshake: %w", hsErr)
	}
	if controlling {
		h.log.Debug("punch: handshake ok", "component", "punch",
			"remote_srflx", remoteSrflxes, "remote_nat", remoteNat, "rtt_ms", rttMs)
	} else {
		h.log.Debug("punch: handshake ok", "component", "punch",
			"remote_srflx", remoteSrflxes, "remote_nat", remoteNat)
	}

	// --- Phase 2: async ---
	clientTLS, tlsErr := quicClientTLSWithCert(localCert, expectRemote)
	if tlsErr != nil {
		return fmt.Errorf("punch: client tls: %w", tlsErr)
	}

	// Detect remote Symmetric NAT via self-reported NAT type.
	// When remote has Symmetric NAT, each outbound mapping uses a unique port;
	// spray around the reported srflx to increase the chance of hitting the
	// actual port the remote's NAT allocates when firing back at us.
	fireTargets := remoteSrflxes
	if remoteNat == natsense.NATSymmetric && len(remoteSrflxes) > 0 {
		fireTargets = expandSymmetricPunch(remoteSrflxes[0], punchSymmetricSpread)
		h.log.Debug("punch: remote symmetric NAT, spraying ports",
			"component", "punch", "controlling", controlling,
			"base", remoteSrflxes[0], "spread", punchSymmetricSpread,
			"n_targets", len(fireTargets))
	}

	// Register for incoming connections from expectRemote via h.qListen.
	// Accept() routes matching connections here; Delete runs in the driver
	// goroutine so the entry stays valid for the full phase-2 lifetime.
	punchCh := make(chan quic.Connection, 4)
	if _, loaded := h.punchExpect.LoadOrStore(expectRemote, punchCh); loaded {
		// A concurrent punch to this peer is already in progress. Let the ICE
		// path proceed independently; close outCh so the caller's range loop
		// terminates immediately without treating this as a fatal error.
		close(outCh)
		return nil
	}

	// Total budget for phase 2 caps both rounds plus the inter-round gap.
	phase2Budget := punchRetryDelay + time.Duration(punchMaxRounds)*punchFireTimeout + time.Second
	phase2Ctx, phase2Cancel := context.WithTimeout(ctx, phase2Budget)

	// winCh buffers connections from the concurrent accept and dial goroutines.
	// Capacity: len(fireTargets) dial wins + cap(punchCh) incoming wins (4) + 1 spare.
	winCh := make(chan punchWin, 1+len(fireTargets)+4)

	// sendersWG tracks every goroutine that may write to winCh.
	// The driver uses it to know when winCh is permanently idle so it can
	// drain and close any connections that arrived after the driver stopped
	// reading (e.g. a dial that completed just after the 100 ms drain window).
	var sendersWG sync.WaitGroup

	// Accept goroutine: continuously routes all incoming punch connections from
	// punchCh (fed by host.Accept) into winCh for the full phase-2 lifetime.
	// A loop is used so that connections from both directions (callee's fire and
	// caller's fire) are all forwarded; the driver decides which ones to send to
	// outCh. Exits when phase2Ctx is cancelled at end of driver goroutine.
	sendersWG.Add(1)
	go func() {
		defer sendersWG.Done()
		for {
			select {
			case qc := <-punchCh:
				ra, _ := qc.RemoteAddr().(*net.UDPAddr)
				winCh <- punchWin{qc: qc, peer: ra, teardown: func() {}}
			case <-phase2Ctx.Done():
				return
			}
		}
	}()

	// Phase-2 driver goroutine: runs fire rounds and forwards wins to outCh.
	go func() {
		defer h.punchExpect.Delete(expectRemote)
		defer func() {
			sendersWG.Wait()
			for {
				select {
				case stray := <-winCh:
					_ = stray.qc.CloseWithError(0, "punch: orphaned connection cleanup")
					stray.teardown()
				default:
					return
				}
			}
		}()
		defer close(outCh)
		defer phase2Cancel()

		for round := 0; round < punchMaxRounds; round++ {
			if round > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(punchRetryDelay):
				}
			}

			h.log.Debug("punch: fire round", "component", "punch",
				"controlling", controlling, "round", round+1, "targets", remoteSrflxes)

			// Sync: caller sends punch-go and waits RTT/2; callee fires on receipt.
			if controlling {
				if wErr := sess.writeFrame(ctx, signaling.Frame{T: "punch-go"}); wErr != nil {
					h.log.Debug("punch: send punch-go failed", "component", "punch", "round", round+1, "err", wErr)
					return
				}
				if half := time.Duration(rttMs/2) * time.Millisecond; half > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(half):
					}
				}
			} else {
				waitCtx, waitCancel := context.WithTimeout(ctx, punchGoWaitTimeout)
				_, waitErr := punchRecvFrame(waitCtx, sess.punchCh, "punch-go")
				waitCancel()
				if waitErr != nil {
					h.log.Debug("punch: wait punch-go failed", "component", "punch", "round", round+1, "err", waitErr)
					return
				}
			}

			// Fire: dial all targets in parallel via the host's main quicTr;
			// race against the incoming accept from punchCh / punchExpect.
			fireCtx, fireCancel := context.WithTimeout(phase2Ctx, punchFireTimeout)
			for _, srflxStr := range fireTargets {
				srflxStr := srflxStr
				sendersWG.Add(1)
				go func() {
					defer sendersWG.Done()
					addr, rErr := net.ResolveUDPAddr("udp4", srflxStr)
					if rErr != nil {
						return
					}
					dialedQC, dErr := h.quicTr.Dial(fireCtx, addr, clientTLS, qcfg)
					if dErr != nil {
						return
					}
					ra, _ := dialedQC.RemoteAddr().(*net.UDPAddr)
					winCh <- punchWin{qc: dialedQC, peer: ra, teardown: func() {}}
				}()
			}

			select {
			case w := <-winCh:
				fireCancel()
				h.log.Debug("punch: connection established", "component", "punch",
					"controlling", controlling, "round", round+1, "peer", w.peer)
				select {
				case outCh <- w:
				case <-phase2Ctx.Done():
					return
				}

				// Forward every subsequent win until the phase-2 budget expires.
				// Both directions fire simultaneously; additional connections may
				// arrive from sprayed ports or the reverse-direction dial. Keeping
				// all of them gives the upper layer (onConn) maximum fallback candidates
				// in case the first connection's data-channel handshake fails.
				// Unfowarded wins are not closed here: the QUIC transport holds them
				// and they idle out naturally (per the "don't discard live connections" principle).
				for {
					select {
					case w2 := <-winCh:
						h.log.Debug("punch: additional connection established", "component", "punch",
							"controlling", controlling, "peer", w2.peer)
						select {
						case outCh <- w2:
						case <-phase2Ctx.Done():
							return
						}
					case <-phase2Ctx.Done():
						return
					}
				}

			case <-fireCtx.Done():
				fireCancel()
				h.log.Debug("punch: fire timeout", "component", "punch",
					"controlling", controlling, "round", round+1)
			}
		}
		// All rounds exhausted without any connection.
	}()

	return nil
}

// punchCallerHandshake sends punch-init (with localNat) and waits for punch-ack.
// Returns the remote's srflx addresses, remote's self-reported NAT type, and RTT in ms.
func punchCallerHandshake(ctx context.Context, sess *iceSession, localAddrs []string, localNat uint8) (remoteSrflxes []string, remoteNat uint8, rttMs int64, err error) {
	initTs := time.Now().UnixMilli()
	if err = sess.writeFrame(ctx, signaling.Frame{
		T:     "punch-init",
		Addrs: localAddrs,
		Ts:    initTs,
		Nat:   localNat,
	}); err != nil {
		return nil, 0, 0, fmt.Errorf("send punch-init: %w", err)
	}

	ack, err := punchRecvFrame(ctx, sess.punchCh, "punch-ack")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("recv punch-ack: %w", err)
	}

	rtt := time.Now().UnixMilli() - ack.Ts // ack echoes our initTs
	if rtt < 0 {
		rtt = 0
	}
	return ack.Addrs, ack.Nat, rtt, nil
}

// punchCalleeHandshake waits for punch-init and replies with punch-ack (with localNat).
// Returns the remote's srflx addresses and remote's self-reported NAT type.
func punchCalleeHandshake(ctx context.Context, sess *iceSession, localAddrs []string, localNat uint8) (remoteSrflxes []string, remoteNat uint8, err error) {
	initFr, err := punchRecvFrame(ctx, sess.punchCh, "punch-init")
	if err != nil {
		return nil, 0, fmt.Errorf("recv punch-init: %w", err)
	}

	if err = sess.writeFrame(ctx, signaling.Frame{
		T:     "punch-ack",
		Addrs: localAddrs,
		Ts:    initFr.Ts, // echo timestamp for RTT measurement
		Nat:   localNat,
	}); err != nil {
		return nil, 0, fmt.Errorf("send punch-ack: %w", err)
	}

	return initFr.Addrs, initFr.Nat, nil
}

// punchRecvFrame reads from ch until a frame of wantType arrives or ctx is done.
// Frames of unexpected types are silently dropped.
func punchRecvFrame(ctx context.Context, ch <-chan signaling.Frame, wantType string) (signaling.Frame, error) {
	for {
		select {
		case <-ctx.Done():
			return signaling.Frame{}, fmt.Errorf("waiting for %s: %w", wantType, ctx.Err())
		case fr := <-ch:
			if fr.T == wantType {
				return fr, nil
			}
		}
	}
}
