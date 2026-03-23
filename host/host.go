// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package host is the Phase 2a SDK: DHT + QUIC, nat-sense, Publish/Resolve/Connect/Accept.
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
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/natsense"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 30 * time.Second,
		MaxIdleTimeout:       90 * time.Second,
	}
}

// Config wires DHT + QUIC (Phase 2a).
type Config struct {
	KeyStore crypto.KeyStore
	// ListenAddr is the DHT UDP bind address ("udp4"), e.g. ":5001".
	ListenAddr string
	// QUICListenAddr, if non-empty, is a separate UDP bind for QUIC.
	QUICListenAddr string
	PrivateKey       ed25519.PrivateKey
	MinObservedPeers int
	FallbackHost     string
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
	addr a2al.Address
	priv ed25519.PrivateKey
	cert tls.Certificate
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

// BuildEndpointPayload builds quic:// for QUIC reachability.
func (h *Host) BuildEndpointPayload() (protocol.EndpointPayload, error) {
	ua := h.QUICLocalAddr()
	port := ua.Port
	hostStr := h.cfg.FallbackHost
	if th, _, ok := h.sense.TrustedUDP(); ok {
		hostStr = th
	}
	if hostStr == "" {
		ip := ua.IP
		if ip4 := ip.To4(); ip4 != nil && !ip.IsUnspecified() {
			hostStr = ip4.String()
		}
	}
	if hostStr == "" {
		ip := h.DHTLocalAddr().IP
		if ip4 := ip.To4(); ip4 != nil && !ip.IsUnspecified() {
			hostStr = ip4.String()
		}
	}
	if hostStr == "" {
		// Last resort: probe the OS-selected outbound IP (no packets sent).
		// On a loopback-only machine this yields 127.0.0.1; on a routed machine
		// it yields the primary outbound interface IP.
		if ip := outboundIP(); ip != nil {
			hostStr = ip.String()
		}
	}
	if hostStr == "" {
		return protocol.EndpointPayload{}, errors.New("a2al/host: cannot determine advertise host; set FallbackHost or bind a specific IP")
	}
	ep := "quic://" + net.JoinHostPort(hostStr, strconv.Itoa(port))
	return protocol.EndpointPayload{
		Endpoints: []string{ep},
		NatType:   h.sense.InferNATType(),
	}, nil
}

func (h *Host) PublishEndpoint(ctx context.Context, seq uint64, ttl uint32) error {
	ep, err := h.BuildEndpointPayload()
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	rec, err := protocol.SignEndpointRecord(h.priv, h.addr, ep, seq, uint64(now.Unix()), ttl)
	if err != nil {
		return err
	}
	return h.node.PublishEndpointRecord(ctx, rec)
}

func (h *Host) Resolve(ctx context.Context, target a2al.Address) (*protocol.EndpointRecord, error) {
	q := dht.NewQuery(h.node)
	return q.Resolve(ctx, a2al.NodeIDFromAddress(target))
}

// Connect dials the remote agent over QUIC with mutual TLS.
// After the QUIC handshake, it opens a control stream and sends the
// agent-route frame (4-byte magic + 21-byte target Address) so the
// server can route the connection even when TLS SNI is camouflaged.
func (h *Host) Connect(ctx context.Context, expectRemote a2al.Address, udpAddr *net.UDPAddr) (quic.Connection, error) {
	cliTLS, err := quicClientTLS(h.priv, expectRemote)
	if err != nil {
		return nil, err
	}
	conn, err := h.quicTr.Dial(ctx, udpAddr, cliTLS, defaultQUICConfig())
	if err != nil {
		return nil, err
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "agent-route stream failed")
		return nil, fmt.Errorf("a2al/host: open agent-route stream: %w", err)
	}
	frame := append(agentRouteMagic, expectRemote[:]...)
	if _, err := str.Write(frame); err != nil {
		_ = conn.CloseWithError(1, "agent-route write failed")
		return nil, fmt.Errorf("a2al/host: write agent-route frame: %w", err)
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
	ac := &AgentConn{Connection: conn, Local: h.addr}

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
	var errs []error
	if h.qListen != nil {
		errs = append(errs, h.qListen.Close())
	}
	if h.quicTr != nil {
		errs = append(errs, h.quicTr.Close())
	}
	if h.mux != nil {
		errs = append(errs, h.mux.Close())
	}
	errs = append(errs, h.node.Close())
	return errors.Join(errs...)
}

// FirstQUICAddr extracts the first quic:// (or legacy udp://) endpoint as a UDP address.
func FirstQUICAddr(er *protocol.EndpointRecord) (*net.UDPAddr, error) {
	if er == nil {
		return nil, errors.New("a2al/host: nil endpoint record")
	}
	for _, e := range er.Endpoints {
		u, err := url.Parse(e)
		if err != nil || (u.Scheme != "quic" && u.Scheme != "udp") || u.Host == "" {
			continue
		}
		return net.ResolveUDPAddr("udp4", u.Host)
	}
	return nil, errors.New("a2al/host: no quic endpoint in record")
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
