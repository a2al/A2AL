// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package host is the Phase 2 SDK: DHT + QUIC, nat-sense, multi-candidate endpoints (2b),
// optional UPnP, Happy Eyeballs dial, Publish/Resolve/Connect/Accept.
//
// A Host manages the node-level resources (DHT, QUIC transport). One or more
// agents (each identified by a unique Address) share the same QUIC listener
// via TLS SNI routing (spec Phase 2a "mux" module).
//
// When Config.QUICListenAddr is empty, DHT and QUIC share one UDP port via
// UDPMux (spec target). When QUICListenAddr is set, QUIC uses a separate
// socket — recommended until mux is hardened on all platforms.
package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/identity"
	"github.com/a2al/a2al/natmap"
	"github.com/a2al/a2al/natsense"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:    10 * time.Second,
		MaxIdleTimeout:          90 * time.Second,
		MaxIncomingStreams:       100,
		MaxIncomingUniStreams:    10,
	}
}

// Config wires DHT + QUIC.
//
// IPv6 note: currently Host binds udp4 sockets only. The Transport interface,
// protocol wire format (NodeInfo.IP 4/16 bytes, observed_addr 6/18 bytes), and
// endpoint URL model ("quic://[v6]:port") are all IPv6-ready. Dual-stack
// requires changing the socket setup in New() — either "udp" dual-stack or
// separate v4+v6 listeners — and adding v6 candidate collection in candidates.go.
// No interface or data-model changes are expected.
type Config struct {
	KeyStore crypto.KeyStore
	// ListenAddr is the DHT UDP bind address, e.g. ":5001".
	// Currently resolved as udp4; dual-stack (udp / "[::]:port") is planned.
	ListenAddr string
	// QUICListenAddr, if non-empty, is a separate UDP bind for QUIC.
	// Same udp4 constraint as ListenAddr.
	QUICListenAddr string
	PrivateKey       ed25519.PrivateKey
	MinObservedPeers int
	FallbackHost     string
	// DisableUPnP skips IGD port mapping for the QUIC UDP port (Phase 2b). TURN is deferred.
	DisableUPnP bool

	// ICESignalURL is the WebSocket base URL published in endpoint records for ICE trickle (optional).
	ICESignalURL string
	// ICESTUNURLs lists stun: URIs for ICE gathering; empty means default public STUN when no TURN is configured.
	ICESTUNURLs []string
	// ICETURNURLs lists turn: URIs (may include credentials) used locally for ICE relay; not published.
	ICETURNURLs []string
	// ICEPublishTurns lists credential-free turn: hints stored in EndpointPayload.Turns.
	ICEPublishTurns []string
}

// agentRouteMagic is the 4-byte prefix of the agent-route control stream.
// The client opens the first stream and writes: magic(4) + target_address(21).
var agentRouteMagic = []byte{'a', '2', 'r', '1'}

// AgentConn wraps a QUIC connection with the resolved peer and local agent identities.
type AgentConn struct {
	quic.Connection
	// Local is the agent Address that was targeted (agent-route frame, or SNI fallback).
	Local a2al.Address
	// Remote is the connecting peer's Address (from mutual TLS client cert).
	Remote a2al.Address
}

// agentEntry is a registered agent in the SNI router.
type agentEntry struct {
	addr           a2al.Address
	priv           ed25519.PrivateKey
	cert           tls.Certificate
	delegationCBOR []byte // non-nil for Phase 3 delegated agents
}

// Host is the Phase 2a runtime.
type Host struct {
	cfg     Config
	addr    a2al.Address // default (first) agent address
	priv    ed25519.PrivateKey
	mux     *transport.UDPMux
	node    *dht.Node
	sense   *natsense.Sense
	quicTr  *quic.Transport
	qListen *quic.Listener

	agentsMu sync.RWMutex
	agents   map[a2al.Address]*agentEntry

	upnpMu             sync.Mutex
	upnpURL            string
	upnpCleanup        func()
	upnpFailRetryAfter time.Time

	extipMu   sync.Mutex
	extipSnap string    // "ip:port" (STUN) or "ip" (HTTP); empty = not yet resolved
	extipExp  time.Time // cache expiry
}

// New creates a Host with one initial agent identity from cfg.KeyStore.
func New(cfg Config) (*Host, error) {
	if cfg.KeyStore == nil {
		return nil, errors.New("a2al/host: KeyStore required")
	}
	addrs, err := cfg.KeyStore.List()
	if err != nil {
		return nil, err
	}
	if len(addrs) != 1 {
		return nil, errors.New("a2al/host: KeyStore must hold exactly one identity")
	}
	myAddr := addrs[0]

	priv := cfg.PrivateKey
	if priv == nil {
		type exporter interface {
			Ed25519PrivateKey(a2al.Address) (ed25519.PrivateKey, error)
		}
		if ex, ok := cfg.KeyStore.(exporter); ok {
			priv, err = ex.Ed25519PrivateKey(myAddr)
			if err != nil {
				return nil, fmt.Errorf("a2al/host: QUIC private key: %w", err)
			}
		}
	}
	if priv == nil {
		return nil, errors.New("a2al/host: set Config.PrivateKey for QUIC (or use EncryptedKeyStore after Load)")
	}

	min := cfg.MinObservedPeers
	if min == 0 {
		min = 3
	}
	sense := natsense.NewSense(min)

	dhtUDP, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	dhtCfg := dht.Config{
		Keystore: cfg.KeyStore,
		OnObservedAddr: func(reporter a2al.NodeID, wire []byte) {
			sense.Record(reporter, wire)
		},
		RecordAuth: recordAuthPolicy,
	}

	var node *dht.Node
	var mux *transport.UDPMux
	var qt *quic.Transport

	if cfg.QUICListenAddr == "" {
		conn, err := net.ListenUDP("udp4", dhtUDP)
		if err != nil {
			return nil, err
		}
		mux = transport.NewUDPMux(conn)
		mux.StartReadLoop()
		dhtCfg.Transport = mux.DHTTransport()
		node, err = dht.NewNode(dhtCfg)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		qt = &quic.Transport{Conn: mux.QUICPacketConn()}
	} else {
		qUDP, err := net.ResolveUDPAddr("udp4", cfg.QUICListenAddr)
		if err != nil {
			return nil, err
		}
		dConn, err := net.ListenUDP("udp4", dhtUDP)
		if err != nil {
			return nil, err
		}
		qConn, err := net.ListenUDP("udp4", qUDP)
		if err != nil {
			_ = dConn.Close()
			return nil, err
		}
		dhtCfg.Transport = transport.NewUDPTransport(dConn)
		node, err = dht.NewNode(dhtCfg)
		if err != nil {
			_ = dConn.Close()
			_ = qConn.Close()
			return nil, err
		}
		qt = &quic.Transport{Conn: qConn}
	}

	defaultCert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		closeAfterError(mux, node)
		return nil, err
	}

	h := &Host{
		cfg:    cfg,
		addr:   myAddr,
		priv:   priv,
		mux:    mux,
		node:   node,
		sense:  sense,
		quicTr: qt,
		agents: map[a2al.Address]*agentEntry{
			myAddr: {addr: myAddr, priv: priv, cert: defaultCert},
		},
	}

	srvTLS := quicServerTLSWithSNI(defaultCert, h.certForSNI)
	qListen, err := qt.Listen(srvTLS, defaultQUICConfig())
	if err != nil {
		closeAfterError(mux, node)
		return nil, err
	}
	h.qListen = qListen

	node.Start()
	return h, nil
}

// certForSNI is the GetCertificate callback — selects agent cert by TLS SNI.
func (h *Host) certForSNI(sni string) *tls.Certificate {
	addr, err := a2al.ParseAddress(sni)
	if err != nil {
		return nil
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[addr]
	h.agentsMu.RUnlock()
	if !ok {
		return nil
	}
	return &ag.cert
}

// RegisterAgent adds an additional agent identity to this host's SNI router.
// Incoming connections with TLS ServerName matching addr will be served with
// the corresponding certificate. Returns an error if the address is already registered.
func (h *Host) RegisterAgent(addr a2al.Address, priv ed25519.PrivateKey) error {
	cert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		return err
	}
	h.agentsMu.Lock()
	defer h.agentsMu.Unlock()
	if _, exists := h.agents[addr]; exists {
		return fmt.Errorf("a2al/host: agent %s already registered", addr)
	}
	h.agents[addr] = &agentEntry{addr: addr, priv: priv, cert: cert}
	return nil
}

// RegisterDelegatedAgent adds a Phase 3 agent whose operational key is authorized
// by a DelegationProof (delegationCBOR). The proof is embedded in endpoint records
// so DHT nodes can verify the authority of the operational key independently.
func (h *Host) RegisterDelegatedAgent(addr a2al.Address, opPriv ed25519.PrivateKey, delegationCBOR []byte) error {
	cert, err := selfSignedEd25519CertDelegated(opPriv, addr, delegationCBOR)
	if err != nil {
		return err
	}
	h.agentsMu.Lock()
	defer h.agentsMu.Unlock()
	if _, exists := h.agents[addr]; exists {
		return fmt.Errorf("a2al/host: agent %s already registered", addr)
	}
	h.agents[addr] = &agentEntry{addr: addr, priv: opPriv, cert: cert, delegationCBOR: delegationCBOR}
	return nil
}

// UnregisterAgent removes an agent from the SNI router (the default agent
// created at New() cannot be unregistered).
func (h *Host) UnregisterAgent(addr a2al.Address) {
	if addr == h.addr {
		return
	}
	h.agentsMu.Lock()
	delete(h.agents, addr)
	h.agentsMu.Unlock()
}

// RegisteredAgents returns the addresses of all registered agents.
func (h *Host) RegisteredAgents() []a2al.Address {
	h.agentsMu.RLock()
	defer h.agentsMu.RUnlock()
	out := make([]a2al.Address, 0, len(h.agents))
	for a := range h.agents {
		out = append(out, a)
	}
	return out
}

func (h *Host) Node() *dht.Node            { return h.node }
func (h *Host) Sense() *natsense.Sense      { return h.sense }
func (h *Host) Address() a2al.Address        { return h.addr }

func (h *Host) DHTLocalAddr() *net.UDPAddr {
	return h.node.LocalAddr().(*net.UDPAddr)
}

func (h *Host) QUICLocalAddr() *net.UDPAddr {
	return h.quicTr.Conn.LocalAddr().(*net.UDPAddr)
}

func (h *Host) LocalUDPAddr() *net.UDPAddr { return h.DHTLocalAddr() }

func (h *Host) ObserveFromPeers(ctx context.Context, seeds []net.Addr) {
	for _, s := range seeds {
		pi, err := h.node.PingIdentity(ctx, s)
		if err != nil || len(pi.ObservedWire) == 0 {
			continue
		}
		h.sense.Record(pi.NodeID, pi.ObservedWire)
	}
}

// BuildEndpointPayload builds ordered, deduplicated quic:// candidates (Phase 2b).
// UPnP discovery and external IP probing (STUN + HTTP) run concurrently.
func (h *Host) BuildEndpointPayload(ctx context.Context) (protocol.EndpointPayload, error) {
	upCh := make(chan string, 1)
	extCh := make(chan string, 1)
	go func() { upCh <- h.ensureUPnP(ctx) }()
	go func() { extCh <- h.ensureExternalIP(ctx) }()
	up := <-upCh
	ext := <-extCh

	eps, err := h.orderedQUICEndpointStrings(ext, up)
	if err != nil {
		return protocol.EndpointPayload{}, err
	}
	var turns []string
	for _, t := range h.cfg.ICEPublishTurns {
		if strings.Contains(t, "@") {
			continue // never publish credentials to DHT (spec: "TURN凭证绝不进DHT")
		}
		turns = append(turns, t)
	}
	return protocol.EndpointPayload{
		Endpoints: eps,
		NatType:   h.sense.InferNATType(),
		Signal:    h.cfg.ICESignalURL,
		Turns:     turns,
	}, nil
}

const extipCacheTTL = 5 * time.Minute

// ensureExternalIP returns a cached or freshly probed external IP string.
// It first tries STUN (returns "ip:port") then HTTP services (returns "ip").
// Returns "" if both fail.
func (h *Host) ensureExternalIP(ctx context.Context) string {
	h.extipMu.Lock()
	if h.extipSnap != "" && time.Now().Before(h.extipExp) {
		snap := h.extipSnap
		h.extipMu.Unlock()
		return snap
	}
	h.extipMu.Unlock()

	// STUN probe: 3-second budget.
	sctx, scancel := context.WithTimeout(ctx, 3*time.Second)
	stunIP, stunPort := probeSTUN(sctx)
	scancel()

	var snap string
	if stunIP != nil && isPlausibleWANIP(stunIP) {
		snap = net.JoinHostPort(stunIP.String(), strconv.Itoa(int(stunPort)))
	} else {
		// HTTP fallback: 5-second budget.
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		httpIP := httpPublicIP(hctx)
		hcancel()
		if httpIP != nil && isPlausibleWANIP(httpIP) {
			snap = httpIP.String()
		}
	}

	if snap != "" {
		h.extipMu.Lock()
		h.extipSnap = snap
		h.extipExp = time.Now().Add(extipCacheTTL)
		h.extipMu.Unlock()
	}
	return snap
}

func (h *Host) ensureUPnP(ctx context.Context) string {
	if h.cfg.DisableUPnP {
		return ""
	}
	h.upnpMu.Lock()
	if h.upnpURL != "" {
		u := h.upnpURL
		h.upnpMu.Unlock()
		return u
	}
	if time.Now().Before(h.upnpFailRetryAfter) {
		h.upnpMu.Unlock()
		return ""
	}
	h.upnpMu.Unlock()

	lan := natmap.LocalIPv4ForUPnP()
	if lan == "" {
		h.upnpMu.Lock()
		h.upnpFailRetryAfter = time.Now().Add(60 * time.Second)
		h.upnpMu.Unlock()
		return ""
	}
	port := h.QUICLocalAddr().Port
	extIP, extPort, cleanup, err := natmap.MapUDPPort(ctx, port, lan)

	h.upnpMu.Lock()
	defer h.upnpMu.Unlock()
	if err != nil {
		h.upnpFailRetryAfter = time.Now().Add(60 * time.Second)
		return ""
	}
	if h.upnpURL != "" {
		cleanup()
		return h.upnpURL
	}
	h.upnpCleanup = cleanup
	h.upnpURL = natmap.QUICURL(extIP, extPort)
	return h.upnpURL
}

// SymmetricNATReachabilityHint returns a user-facing note when NAT looks symmetric.
// Phase 2b does not guarantee inbound QUIC from arbitrary peers; TURN is deferred.
func (h *Host) SymmetricNATReachabilityHint() string {
	if h.sense.InferNATType() != protocol.NATSymmetric {
		return ""
	}
	return "NAT appears symmetric: inbound QUIC from arbitrary internet peers is not guaranteed without relay (TURN planned for Phase 3). Outbound connects or peers behind compatible NATs may still work; coordinated hole punching may use DHT signaling in a later phase."
}

func (h *Host) PublishEndpoint(ctx context.Context, seq uint64, ttl uint32) error {
	return h.PublishEndpointForAgent(ctx, h.addr, seq, ttl)
}

// PublishEndpointForAgent publishes an endpoint record signed by the given registered agent.
// For Phase 3 delegated agents (registered via RegisterDelegatedAgent), the record embeds
// the DelegationProof so DHT nodes can verify the operational key's authority.
func (h *Host) PublishEndpointForAgent(ctx context.Context, agentAddr a2al.Address, seq uint64, ttl uint32) error {
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	ep, err := h.BuildEndpointPayload(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	var rec protocol.SignedRecord
	if len(ag.delegationCBOR) > 0 {
		rec, err = protocol.SignEndpointRecordDelegated(ag.priv, ag.delegationCBOR, agentAddr, ep, seq, uint64(now.Unix()), ttl)
	} else {
		rec, err = protocol.SignEndpointRecord(ag.priv, agentAddr, ep, seq, uint64(now.Unix()), ttl)
	}
	if err != nil {
		return err
	}
	return h.node.PublishEndpointRecord(ctx, rec)
}

// PublishRecord pushes a signed sovereign record (RecType 0x01–0x0F) to the DHT.
// Returns an error if rec is not a sovereign-category record; use
// PublishTopicRecord / host mailbox APIs for other categories.
func (h *Host) PublishRecord(ctx context.Context, rec protocol.SignedRecord) error {
	if protocol.RecordCategory(rec.RecType) != protocol.CategorySovereign {
		return errors.New("a2al/host: PublishRecord is for sovereign records only; use PublishTopicRecord/SendMailbox for other categories")
	}
	return h.node.PublishEndpointRecord(ctx, rec)
}

func (h *Host) Resolve(ctx context.Context, target a2al.Address) (*protocol.EndpointRecord, error) {
	q := dht.NewQuery(h.node)
	return q.Resolve(ctx, a2al.NodeIDFromAddress(target))
}

// FindRecords runs iterative FIND_VALUE for the given RecType filter (0 = all types).
func (h *Host) FindRecords(ctx context.Context, target a2al.Address, recType uint8) ([]protocol.SignedRecord, error) {
	q := dht.NewQuery(h.node)
	return q.FindRecords(ctx, a2al.NodeIDFromAddress(target), recType)
}

// Connect dials the remote agent over QUIC with mutual TLS.
// After the QUIC handshake, it opens a control stream and sends the
// agent-route frame (4-byte magic + 21-byte target Address) so the
// server can route the connection even when TLS SNI is camouflaged.
func (h *Host) Connect(ctx context.Context, expectRemote a2al.Address, udpAddr *net.UDPAddr) (quic.Connection, error) {
	return h.dialAndAgentRoute(ctx, h.priv, expectRemote, udpAddr)
}

func writeAgentRouteFrame(ctx context.Context, conn quic.Connection, target a2al.Address) error {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("a2al/host: open agent-route stream: %w", err)
	}
	frame := append(agentRouteMagic, target[:]...)
	if _, err := str.Write(frame); err != nil {
		return fmt.Errorf("a2al/host: write agent-route frame: %w", err)
	}
	return nil
}

func (h *Host) dialAndAgentRoute(ctx context.Context, localPriv ed25519.PrivateKey, expectRemote a2al.Address, udpAddr *net.UDPAddr) (quic.Connection, error) {
	cliTLS, err := quicClientTLS(localPriv, expectRemote)
	if err != nil {
		return nil, err
	}
	conn, err := h.quicTr.Dial(ctx, udpAddr, cliTLS, defaultQUICConfig())
	if err != nil {
		return nil, err
	}
	if err := writeAgentRouteFrame(ctx, conn, expectRemote); err != nil {
		_ = conn.CloseWithError(1, "agent-route failed")
		return nil, err
	}
	return conn, nil
}

// Accept waits for an incoming QUIC connection and returns an AgentConn.
//
// Agent routing priority:
//  1. Agent-route control stream (first stream: magic + 21-byte Address) — canonical.
//  2. TLS SNI (Address hex) — fast-path hint when not camouflaged.
//  3. Default to the host's own Address.
//
// Remote peer AID is extracted from the mutual TLS client certificate.
func (h *Host) Accept(ctx context.Context) (*AgentConn, error) {
	conn, err := h.qListen.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return h.agentConnFromQUIC(ctx, conn, h.addr)
}

func (h *Host) agentConnFromQUIC(ctx context.Context, conn quic.Connection, fallbackLocal a2al.Address) (*AgentConn, error) {
	ac := &AgentConn{Connection: conn, Local: fallbackLocal}

	state := conn.ConnectionState().TLS
	if remote, err := peerAddrFromTLSState(state); err == nil {
		ac.Remote = remote
	}

	// Try agent-route control stream (canonical).
	if target, err := readAgentRouteFrame(ctx, conn); err == nil {
		h.agentsMu.RLock()
		_, ok := h.agents[target]
		h.agentsMu.RUnlock()
		if ok {
			ac.Local = target
		}
	} else if sni := state.ServerName; sni != "" {
		// Fallback: TLS SNI.
		if addr, err := a2al.ParseAddress(sni); err == nil {
			h.agentsMu.RLock()
			_, ok := h.agents[addr]
			h.agentsMu.RUnlock()
			if ok {
				ac.Local = addr
			}
		}
	}
	return ac, nil
}

// readAgentRouteFrame reads the 25-byte agent-route frame (4 magic + 21 address)
// from the first QUIC stream opened by the connecting peer.
func readAgentRouteFrame(ctx context.Context, conn quic.Connection) (a2al.Address, error) {
	str, err := conn.AcceptStream(ctx)
	if err != nil {
		return a2al.Address{}, err
	}
	const frameLen = 4 + 21
	buf := make([]byte, frameLen)
	n := 0
	for n < frameLen {
		r, err := str.Read(buf[n:])
		n += r
		if err != nil {
			return a2al.Address{}, err
		}
	}
	if string(buf[:4]) != string(agentRouteMagic) {
		return a2al.Address{}, errors.New("a2al/host: bad agent-route magic")
	}
	var addr a2al.Address
	copy(addr[:], buf[4:])
	return addr, nil
}

// StartDebugHTTP listens on addr and serves /debug/* JSON for both DHT
// and Phase 2 host state. Returns a stop function.
func (h *Host) StartDebugHTTP(addr string) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           h.DebugHTTPHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
		_ = ln.Close()
	}, nil
}

func (h *Host) Close() error {
	h.upnpMu.Lock()
	if h.upnpCleanup != nil {
		h.upnpCleanup()
		h.upnpCleanup = nil
	}
	h.upnpURL = ""
	h.upnpFailRetryAfter = time.Time{}
	h.upnpMu.Unlock()

	var errs []error
	if h.qListen != nil {
		errs = append(errs, h.qListen.Close())
	}
	if h.quicTr != nil {
		// quic.Transport.Close waits for active connections to drain (up to
		// MaxIdleTimeout). Cap the wait at 3 s; on timeout force-close the
		// underlying packet conn so the goroutine unblocks quickly.
		done := make(chan struct{})
		go func() {
			_ = h.quicTr.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = h.quicTr.Conn.Close()
		}
	}
	if h.mux != nil {
		errs = append(errs, h.mux.Close())
	}
	errs = append(errs, h.node.Close())
	return errors.Join(errs...)
}

// FirstQUICAddr returns the first quic:// (or legacy udp://) endpoint as a UDP address.
func FirstQUICAddr(er *protocol.EndpointRecord) (*net.UDPAddr, error) {
	addrs, err := QUICDialTargets(er)
	if err != nil {
		return nil, err
	}
	return addrs[0], nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// outboundIP returns the preferred outbound IP without sending any packets.
// It does this by connecting a UDP socket to a public address and reading
// the local address the OS assigned.
func outboundIP() net.IP {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func peerAddrFromTLSState(state tls.ConnectionState) (a2al.Address, error) {
	return PeerAddressFromConn(state.PeerCertificates)
}

func closeAfterError(mux *transport.UDPMux, node *dht.Node) {
	if mux != nil {
		_ = mux.Close()
	}
	if node != nil {
		_ = node.Close()
	}
}

// recordAuthPolicy is the DHT store authority policy for a2ald hosts.
// Phase 4: sovereign records must use key == NodeID(sr.Address); Topic/Mailbox skip address binding.
func recordAuthPolicy(key a2al.NodeID, sr protocol.SignedRecord, now time.Time) error {
	cat := protocol.RecordCategory(sr.RecType)
	if cat == protocol.CategoryTopic || cat == protocol.CategoryMailbox {
		return nil
	}
	var recAddr a2al.Address
	copy(recAddr[:], sr.Address)
	if key != a2al.NodeIDFromAddress(recAddr) {
		return errors.New("a2al/host: sovereign record DHT key mismatch")
	}
	signerAddr, err := crypto.AddressFromPublicKey(sr.Pubkey)
	if err != nil {
		return err
	}
	if signerAddr == recAddr {
		return nil
	}
	if len(sr.Delegation) == 0 {
		return errors.New("a2al/host: record address/key mismatch and no delegation")
	}
	proof, err := identity.ParseDelegationProof(sr.Delegation)
	if err != nil {
		return fmt.Errorf("a2al/host: delegation: %w", err)
	}
	if !bytes.Equal(proof.OpPub, sr.Pubkey) {
		return errors.New("a2al/host: delegation op key mismatch")
	}
	if !bytes.Equal(proof.AgentAddr, sr.Address) {
		return errors.New("a2al/host: delegation address mismatch")
	}
	return identity.VerifyDelegation(proof, uint64(now.Unix()), nil)
}
