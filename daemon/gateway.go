// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// parseServiceTCP splits a service_tcp value into (scheme, addr).
// Recognised prefixes: "https://", "http://".
// Anything else is returned as ("tcp", raw) for plain TCP forwarding.
func parseServiceTCP(raw string) (scheme, addr string) {
	if strings.HasPrefix(raw, "https://") {
		return "https", strings.TrimPrefix(raw, "https://")
	}
	if strings.HasPrefix(raw, "http://") {
		return "http", strings.TrimPrefix(raw, "http://")
	}
	return "tcp", raw
}

// dialServiceTCP opens a connection to the service described by serviceTCP.
// For "https://…" it wraps the connection in TLS with InsecureSkipVerify —
// the daemon and the backend share the same trust domain (local/LAN).
func dialServiceTCP(ctx context.Context, serviceTCP string, timeout time.Duration) (net.Conn, error) {
	scheme, addr := parseServiceTCP(serviceTCP)
	d := &net.Dialer{Timeout: timeout}
	if scheme == "https" {
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
	return d.DialContext(ctx, "tcp", addr)
}

// sessionInfo is the per-connection metadata stored while a gateway TCP bridge
// is active. It is exposed via GET /sessions/{port}.
type sessionInfo struct {
	CallerAID    string    `json:"caller_aid"`
	CallerPubkey string    `json:"caller_pubkey"` // base64url-encoded Ed25519 public key
	LocalAID     string    `json:"local_aid"`
	ConnectedAt  time.Time `json:"connected_at"`

	// Data-plane byte counters. Updated atomically during bridging.
	// BytesUp   = bytes forwarded TCP(service) → QUIC stream.
	// BytesDown = bytes forwarded QUIC stream → TCP(service).
	BytesUp      atomic.Int64 `json:"-"`
	BytesDown    atomic.Int64 `json:"-"`
	LastProgress atomic.Int64 `json:"-"` // unix nano; updated whenever either direction advances
}

// sessionSnapshot is the JSON-serialisable view of sessionInfo.
type sessionSnapshot struct {
	CallerAID      string    `json:"caller_aid"`
	CallerPubkey   string    `json:"caller_pubkey"`
	LocalAID       string    `json:"local_aid"`
	ConnectedAt    time.Time `json:"connected_at"`
	BytesUp        int64     `json:"bytes_up"`
	BytesDown      int64     `json:"bytes_down"`
	LastProgressAt time.Time `json:"last_progress_at,omitempty"`
}

func (s *sessionInfo) snapshot() sessionSnapshot {
	snap := sessionSnapshot{
		CallerAID:    s.CallerAID,
		CallerPubkey: s.CallerPubkey,
		LocalAID:     s.LocalAID,
		ConnectedAt:  s.ConnectedAt,
		BytesUp:      s.BytesUp.Load(),
		BytesDown:    s.BytesDown.Load(),
	}
	if ns := s.LastProgress.Load(); ns != 0 {
		snap.LastProgressAt = time.Unix(0, ns)
	}
	return snap
}

const (
	maxGatewayConns   = 1024
	maxStreamsPerConn = 100
	tcpBridgeDeadline = 30 * time.Second

	// gatewayDHTFallbackMaxMsg caps a speculative DHT-message read on a
	// stream that arrived on a connection with no service_tcp configured.
	// Mirrors host's internal Mode B stream size cap (kept as a separate
	// constant to avoid exporting a host-internal value across the package
	// boundary).
	gatewayDHTFallbackMaxMsg = 64 << 10 // 64 KiB

	// gatewayDHTFallbackReadTimeout bounds how long a goroutine/stream is
	// held open waiting for data before falling back to the original
	// reject-and-close behavior. Sized to a generous DHT RPC round trip.
	gatewayDHTFallbackReadTimeout = 3 * time.Second
)

func (d *Daemon) gatewayAcceptLoop(ctx context.Context) {
	go d.sharedTransportAcceptLoop(ctx)
	for {
		ac, err := d.h.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Debug("accept", "reason", err)
			continue
		}
		if !d.tryAcquireGatewayConn() {
			d.log.Warn("gateway: max connections reached", "limit", maxGatewayConns)
			_ = ac.CloseWithError(1, "too many connections")
			continue
		}
		go func() {
			defer d.releaseGatewayConn()
			d.serveGatewayConn(ctx, ac)
		}()
	}
}

// sharedTransportAcceptLoop accepts connections that arrive on shared ICE
// transports (callers reusing an existing hole-punched path for additional
// agents). It feeds the same serveGatewayConn pipeline as the main listener.
func (d *Daemon) sharedTransportAcceptLoop(ctx context.Context) {
	for {
		ac, err := d.h.AcceptShared(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Debug("accept shared", "reason", err)
			continue
		}
		if !d.tryAcquireGatewayConn() {
			d.log.Warn("gateway: max connections reached (shared)", "limit", maxGatewayConns)
			_ = ac.CloseWithError(1, "too many connections")
			continue
		}
		go func() {
			defer d.releaseGatewayConn()
			d.serveGatewayConn(ctx, ac)
		}()
	}
}

func (d *Daemon) tryAcquireGatewayConn() bool {
	for {
		cur := d.gatewayConns.Load()
		if cur >= maxGatewayConns {
			return false
		}
		if d.gatewayConns.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (d *Daemon) releaseGatewayConn() {
	d.gatewayConns.Add(-1)
}

// gatewayHandshakeTimeout caps the a2r1/a2r2 control-stream exchange on the
// acceptor side.  Normal round-trips complete in milliseconds; 15 s is a
// generous upper bound that prevents a single slow or malicious peer from
// blocking this goroutine indefinitely.
const gatewayHandshakeTimeout = 15 * time.Second

func (d *Daemon) serveGatewayConn(ctx context.Context, ac *host.AgentConn) {
	// Resolve the target local agent via the a2r1/a2r2 control-stream
	// exchange.  This runs here (inside a goroutine, off the accept loop) so
	// that one bad connection can never stall Accept() for all other callers.
	//
	// ICE connections (AcceptICEViaSignal) must NOT call this path: their
	// Stream 0 has already been consumed inside acceptICEToQUIC's onConn
	// callback for winner selection.  Those callers invoke
	// serveResolvedGatewayConn directly to skip this step.
	csCtx, csCancel := context.WithTimeout(ctx, gatewayHandshakeTimeout)
	if local, err := d.h.ResolveInboundAgent(csCtx, ac.Connection); err == nil {
		ac.Local = local
	}
	csCancel()
	d.serveResolvedGatewayConn(ctx, ac)
}

// serveResolvedGatewayConn is the second half of connection serving: registry
// lookup, identity check, and the AcceptStream dispatch loop.
//
// Precondition: ac.Local must already be resolved and Stream 0 must have been
// consumed by the caller.  Use serveGatewayConn when Stream 0 has not yet
// been read (direct and shared-transport connections).
//
// Currently called directly by the ICE path (AcceptICEViaSignal, where Stream 0
// was consumed by acceptICEToQUIC's onConn callback) and indirectly by
// serveGatewayConn for direct/shared connections.
//
// When a new connection source is added: if its host-layer Accept variant
// internally consumes Stream 0 (as AcceptICEViaSignal does), call this
// function directly.  If it does not consume Stream 0, call serveGatewayConn.
// This distinction will be eliminated once §7C (unified Accept queue) lands.
func (d *Daemon) serveResolvedGatewayConn(ctx context.Context, ac *host.AgentConn) {
	d.log.Debug("gateway: quic accepted", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
	d.regMu.RLock()
	reg := d.reg.Get(ac.Local)
	d.regMu.RUnlock()

	// Network-layer identity check: accept connections for any AID that
	// belongs to this node — either a registered application agent or the
	// node's own default AID (which exists intrinsically and is valid as a
	// network endpoint regardless of whether it has a service_tcp configured).
	// Reject only AIDs that are neither registered nor the node identity.
	if reg == nil && ac.Local != d.nodeAddr {
		d.log.Warn("gateway: unknown local agent", "aid", ac.Local.String())
		_ = ac.CloseWithError(1, "unknown agent")
		return
	}

	// Application-layer service address: empty for the node AID unless remote
	// admin is on (then the Web UI listen address). Mailbox / DHT fallback
	// still run without crossing this door.
	serviceTCP := ""
	if reg != nil {
		serviceTCP = reg.ServiceTCP
	} else if ac.Local == d.nodeAddr && d.remoteAdminEnabled() {
		serviceTCP = d.remoteAdminServiceTCP()
	}

	defer ac.CloseWithError(0, "gateway closed")
	var streamCount atomic.Int64
	for {
		str, err := ac.AcceptStream(ctx)
		if err != nil {
			d.log.Debug("gateway: accept stream done", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String(), "reason", err)
			return
		}
		if streamCount.Load() >= maxStreamsPerConn {
			_ = str.Close()
			continue
		}
		streamCount.Add(1)
		go func() {
			defer streamCount.Add(-1)
			d.dispatchInboundStream(ac, str, serviceTCP)
		}()
	}
}

const streamMagicLen = 4

type inboundMagicHandler func(ac *host.AgentConn, str quic.Stream, serviceTCP string)

func (d *Daemon) initStreamTable() {
	d.streamByMagic = map[string]inboundMagicHandler{
		protocol.MagicMailboxFrame: func(ac *host.AgentConn, str quic.Stream, _ string) {
			d.acceptMailboxFrame(ac, str)
			_ = str.Close()
		},
		protocol.MagicGroupSync: func(ac *host.AgentConn, str quic.Stream, _ string) {
			d.acceptGroupSync(ac, str)
		},
		protocol.MagicServiceStream: func(ac *host.AgentConn, str quic.Stream, serviceTCP string) {
			d.acceptServiceAdmission(ac, str, serviceTCP)
		},
		protocol.MagicCAS: func(ac *host.AgentConn, str quic.Stream, _ string) {
			d.acceptCAS(ac, str)
		},
		protocol.MagicEnvelope: func(ac *host.AgentConn, str quic.Stream, _ string) {
			d.acceptEnvelope(ac, str)
		},
	}
}

func (d *Daemon) streamHandler(magic string) inboundMagicHandler {
	d.streamOnce.Do(d.initStreamTable)
	return d.streamByMagic[magic]
}

// looksLikeA2Magic reports a 4-byte prefix of the form "a2??". Unknown such
// magics must not be restored and bridged into service_tcp.
func looksLikeA2Magic(magic [4]byte, n int) bool {
	return n == streamMagicLen && magic[0] == 'a' && magic[1] == '2'
}

// takeStreamMagic reads at most 4 bytes from r. Unlike bufio.Peek — whose
// buffer is at least 16 bytes and will over-read a coalesced QUIC STREAM
// payload — this never consumes more than 4 bytes from the underlying reader.
func takeStreamMagic(r io.Reader) (magic [4]byte, n int, err error) {
	n, err = io.ReadFull(r, magic[:])
	return magic, n, err
}

// restorePrefix prepends prefix in front of r so a handler that did not
// recognise the 4-byte magic still sees the original stream start.
func restorePrefix(prefix []byte, r io.Reader) io.Reader {
	if len(prefix) == 0 {
		return r
	}
	return io.MultiReader(bytes.NewReader(bytes.Clone(prefix)), r)
}

// dispatchInboundStream reads the first 4 bytes to detect the frame type, then
// looks up the magic table. Unrecognised (or short) prefixes that are not
// "a2??" fall through to bridgeInboundStream (HTTP / DHT / TCP). Unknown a2*
// magics are closed; they must not be bridged into service_tcp.
func (d *Daemon) dispatchInboundStream(ac *host.AgentConn, str quic.Stream, serviceTCP string) {
	magic, n, err := takeStreamMagic(str)
	if n == streamMagicLen && err == nil {
		if h := d.streamHandler(string(magic[:])); h != nil {
			h(ac, str, serviceTCP)
			return
		}
		if looksLikeA2Magic(magic, n) {
			_ = str.Close()
			return
		}
	}

	rest := restorePrefix(magic[:n], str)
	br := bufio.NewReader(rest)
	ps := &peekStream{Reader: br, Stream: str}

	// Node remote-admin has a service_tcp. Misrouted DHT is CBOR, not HTTP;
	// recover it before ACL/bridge so enabling the door does not starve DHT.
	if ac.Local == d.nodeAddr && serviceTCP != "" {
		if b, perr := br.Peek(1); perr == nil && len(b) == 1 && (b[0] < 'A' || b[0] > 'Z') {
			if d.tryHandleAsDHTFallback(ac, ps) {
				return
			}
			return
		}
	}
	allowed := d.decideAccess(ac.Local, ac.Remote, "", ac.RemoteAddr(), accessService)
	d.bridgeInboundStream(ac, ps, serviceTCP, allowed)
}

// acceptServiceAdmission handles a stream whose a2s1 magic has already been
// consumed. Semantics match the previous inline a2s1 path: admission, ACL,
// then TCP bridge.
func (d *Daemon) acceptServiceAdmission(ac *host.AgentConn, str quic.Stream, serviceTCP string) {
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	token, aerr := host.ReadServiceAdmission(str)
	if aerr != nil {
		d.log.Debug("gateway: a2s1 admission read", "err", aerr)
		_ = str.Close()
		return
	}
	allowed := d.decideAccess(ac.Local, ac.Remote, token, ac.RemoteAddr(), accessService)
	reason := ""
	if !allowed {
		reason = "denied"
	}
	if werr := host.WriteAccessResult(str, allowed, reason); werr != nil {
		_ = str.Close()
		return
	}
	_ = str.SetDeadline(time.Time{})
	if !allowed {
		d.log.Warn("gateway: access denied", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
		_ = str.Close()
		return
	}
	br := bufio.NewReader(str)
	ps := &peekStream{Reader: br, Stream: str}
	d.bridgeInboundStream(ac, ps, serviceTCP, true)
}

// peekStream wraps a bufio.Reader over a quic.Stream so that already-buffered
// bytes are visible to the next Read call without changing the quic.Stream interface.
type peekStream struct {
	*bufio.Reader
	quic.Stream
}

func (p *peekStream) Read(b []byte) (int, error) { return p.Reader.Read(b) }

// tryHandleAsDHTFallback recovers a Mode B (DHT control-plane) stream that
// was misrouted into the Mode A gateway — e.g. a punch-pool connection whose
// accept-time classification missed the punchExpect window and fell through
// to serveGatewayConn like an ordinary application connection. Since Mode A
// and Mode B currently share one QUIC accept path (see host.Accept), a
// stream carrying a signed DHT message can end up here instead of the
// punch pool's read loop; without this fallback it is silently dropped,
// which both spams "empty service_tcp" and starves the sender's pending RPC
// into a timeout/retry loop.
//
// Returns true if the stream was consumed as a valid signed DHT message and
// handed to the DHT node (via the same InjectReceived entry point used by
// host's punch pool read loop). Returns false for anything else — including
// oversized, malformed, or empty reads — leaving the caller to apply the
// original reject-and-close semantics.
func (d *Daemon) tryHandleAsDHTFallback(ac *host.AgentConn, str quic.Stream) bool {
	n := d.h.Node()
	if n == nil {
		return false
	}
	_ = str.SetDeadline(time.Now().Add(gatewayDHTFallbackReadTimeout))
	data, err := io.ReadAll(io.LimitReader(str, gatewayDHTFallbackMaxMsg))
	if err != nil || len(data) == 0 {
		return false
	}
	if _, err := protocol.VerifyAndDecode(data); err != nil {
		return false
	}
	n.InjectReceived(data, ac.Connection.RemoteAddr())
	_ = str.Close()
	d.log.Debug("gateway: recovered misrouted dht stream", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
	return true
}

func (d *Daemon) bridgeInboundStream(ac *host.AgentConn, str quic.Stream, serviceTCP string, aclOK bool) {
	if serviceTCP == "" {
		if d.tryHandleAsDHTFallback(ac, str) {
			return
		}
		d.log.Warn("gateway: empty service_tcp", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
		_ = str.Close()
		return
	}
	if !aclOK {
		d.log.Warn("gateway: access denied", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
		rejectAccessStream(str)
		return
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	tcp, err := dialServiceTCP(dialCtx, serviceTCP, 5*time.Second)
	if err != nil {
		d.log.Warn("gateway: tcp dial", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String(), "target", serviceTCP, "err", err)
		_ = str.Close()
		return
	}
	if ac.Local == d.nodeAddr && d.ra != nil {
		d.ra.noteOK(fmt.Sprintf("%p", ac.Connection), ac.Remote.String(), addrIP(ac.RemoteAddr()))
	}

	// Register session so backends can query caller identity via GET /sessions/{port}.
	// The source port of the daemon's outbound TCP connection is the unique key —
	// the backend sees it as conn.RemoteAddr().Port after Accept().
	srcPort := tcp.LocalAddr().(*net.TCPAddr).Port
	si := &sessionInfo{
		CallerAID:   ac.Remote.String(),
		LocalAID:    ac.Local.String(),
		ConnectedAt: time.Now(),
	}
	if certs := ac.ConnectionState().TLS.PeerCertificates; len(certs) > 0 {
		if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
			si.CallerPubkey = base64.RawURLEncoding.EncodeToString(pub)
		}
	}
	d.sessions.Store(srcPort, si)
	defer d.sessions.Delete(srcPort)

	onProgress := func() { si.LastProgress.Store(time.Now().UnixNano()) }
	bridgeTCPQUICStream(str, tcp, &si.BytesUp, &si.BytesDown, onProgress)
}

// closeWriter is implemented by *net.TCPConn, *tls.Conn, and peekConn.
// It half-closes the write side of a TCP connection (sends FIN) without
// closing the read side, allowing the remote peer to detect end-of-response.
type closeWriter interface {
	CloseWrite() error
}

// countingReader wraps an io.Reader, atomically accumulates bytes read into
// count, and calls onProgress after each successful read. Both may be nil.
type countingReader struct {
	r          io.Reader
	count      *atomic.Int64
	onProgress func()
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if c.count != nil {
			c.count.Add(int64(n))
		}
		if c.onProgress != nil {
			c.onProgress()
		}
	}
	return n, err
}

// bridgeTCPQUICStream copies bidirectionally between a QUIC stream and a TCP
// connection. Bytes are accumulated in real time into the provided counters so
// that callers can observe progress while the bridge is still running:
//   - bytesUp:   TCP→QUIC direction
//   - bytesDown: QUIC→TCP direction
//
// bytesUp, bytesDown, and onProgress may all be nil.
func bridgeTCPQUICStream(str quic.Stream, tcp net.Conn, bytesUp, bytesDown *atomic.Int64, onProgress func()) {
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpBridgeDeadline)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cr := &countingReader{r: str, count: bytesDown, onProgress: onProgress}
		_, _ = io.Copy(tcp, cr)
		// Half-close the TCP write side so the peer (browser or backend)
		// receives EOF and knows the response is complete.
		if cw, ok := tcp.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		cr := &countingReader{r: tcp, count: bytesUp, onProgress: onProgress}
		_, _ = io.Copy(str, cr)
		// Signal EOF on the QUIC send side with a clean FIN, not RESET_STREAM.
		_ = str.Close()
	}()
	wg.Wait()
	_ = str.Close()
	_ = tcp.Close()
}
