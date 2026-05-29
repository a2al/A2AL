// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

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
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	ice "github.com/pion/ice/v3"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/identity"
	"github.com/a2al/a2al/natmap"
	"github.com/a2al/a2al/natsense"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/signaling"
	"github.com/a2al/a2al/transport"
)

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  10 * time.Second,
		MaxIdleTimeout:        90 * time.Second,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 10,
		KeepAlivePeriod:       25 * time.Second,
	}
}

// TURNCredentialType selects how TURN credentials are obtained per session.
type TURNCredentialType int

const (
	// TURNCredentialStatic uses a fixed username and password stored in config.
	TURNCredentialStatic TURNCredentialType = iota
	// TURNCredentialHMAC generates time-limited credentials from a shared secret
	// using the coturn use-auth-secret mechanism:
	//   username = strconv.FormatInt(unix_expiry, 10) + ":" + Username
	//   password = base64(HMAC-SHA1(Credential, username))
	TURNCredentialHMAC
	// TURNCredentialRESTAPI fetches short-lived credentials from an HTTP endpoint
	// before each ICE session. The response must be JSON with "username" and
	// "password" (or "credential") fields. Covers Twilio, Metered.ca, etc.
	TURNCredentialRESTAPI
)

// TURNServer describes a TURN relay server and how to obtain credentials for it.
// Credentials are resolved fresh per ICE session; they are never published to the DHT.
type TURNServer struct {
	// URL is the TURN server address without embedded credentials,
	// e.g. "turn:turn.example.com:3478?transport=udp".
	URL string
	// CredentialType selects the credential acquisition method.
	CredentialType TURNCredentialType
	// Username is the static username (Static) or base username prefix (HMAC).
	Username string
	// Credential is the static password (Static), the HMAC shared secret (HMAC),
	// or the Authorization header value for the REST API request (RESTAPI).
	Credential string
	// CredentialURL is the HTTP endpoint that returns short-lived credentials (RESTAPI only).
	CredentialURL string
}

// Config wires DHT + QUIC.
//
// IPv6 note: Host binds dual-stack sockets by default (transport.ListenDualUDP).
// The Transport interface, protocol wire format (NodeInfo.IP 4/16 bytes,
// observed_addr 6/18 bytes), and endpoint URL model ("quic://[v6]:port") are
// all IPv6-ready. Set Config.DisableIPv6 = true to force IPv4-only sockets.
// v6 candidate collection (candidates.go ③④) is the next step (Layer 1 M3).
type Config struct {
	KeyStore crypto.KeyStore
	// ListenAddr is the DHT UDP bind address, e.g. ":5001".
	// Wildcard addresses (":port", "0.0.0.0:port") are promoted to dual-stack
	// ([::]:port on Unix; udp4+udp6 on Windows). Explicit IPv4 addresses
	// (e.g. "1.2.3.4:5001") bind an IPv4-only socket, preserving existing
	// RunNATProbe and candidate-collection behaviour for those deployments.
	// Override with DisableIPv6 = true to force IPv4-only for all addresses.
	ListenAddr string
	// QUICListenAddr, if non-empty, is a separate UDP bind for QUIC.
	// Same dual-stack rules as ListenAddr apply.
	QUICListenAddr   string
	PrivateKey       ed25519.PrivateKey
	MinObservedPeers int
	FallbackHost     string
	// DisableUPnP skips IGD port mapping for the QUIC UDP port (Phase 2b).
	DisableUPnP bool

	// DisableIPv6, when true, forces all sockets to IPv4-only (udp4).
	// Use as an emergency escape hatch if dual-stack causes problems on a
	// specific platform or network environment. Default: false (dual-stack).
	DisableIPv6 bool

	// ICESignalURL is the primary WebSocket base URL for ICE signaling (single URL, backward compat).
	// Superseded by ICESignalURLs when that field is non-empty.
	ICESignalURL string
	// ICESignalURLs lists WebSocket base URLs for ICE signaling (multi-center support).
	// When non-empty, supersedes ICESignalURL. The first URL is also written to
	// EndpointPayload.Signal (CBOR key 3) for backward compatibility with old nodes.
	ICESignalURLs []string
	// ICESTUNURLs lists stun: URIs for ICE gathering; empty means default public STUN when no TURN is configured.
	ICESTUNURLs []string
	// ICETURNURLs lists turn: URIs with embedded credentials for ICE relay (legacy format).
	// Use TURNServers for new deployments; both fields are processed when set.
	ICETURNURLs []string
	// TURNServers lists TURN relay servers with structured credential configuration.
	// Supports Static, HMAC (coturn use-auth-secret), and REST API credential types.
	// Credentials are resolved per ICE session and never published to the DHT.
	TURNServers []TURNServer
	// ICEPublishTurns is retained for decoding old records; new nodes do not publish turns[].
	// Deprecated: callee-pays TURN relay addresses are exchanged via trickle ICE, not the DHT.
	ICEPublishTurns []string
	// Logger is forwarded to the DHT node for diagnostic logging (reply failures, RPC retries).
	// If nil, slog.Default() is used.
	Logger *slog.Logger
	// SeenPeersPath is forwarded to the DHT node for seenPeers persistence (spec §7.3).
	// Empty disables persistence.
	SeenPeersPath string
	// LearnedPathFirst enables learned-path outbound selection in the DHT layer.
	LearnedPathFirst bool
	// ICENetworkTypes lists the ICE network types used for candidate gathering.
	// Defaults to {ice.NetworkTypeUDP4, ice.NetworkTypeUDP6} (dual-stack) when
	// nil or empty. ICE opens its own sockets independently of the main QUIC
	// socket, so IPv6 ICE candidates are collected even on IPv4-only QUIC
	// bindings. Set to {ice.NetworkTypeUDP4} to restrict to IPv4 ICE only.
	ICENetworkTypes []ice.NetworkType
}

// agentRouteMagic is the legacy 4-byte prefix (a2r1). Still recognised on accept
// for backward compatibility with nodes that have not yet upgraded.
var agentRouteMagic = []byte{'a', '2', 'r', '1'}

// agentRouteMagicV2 introduces the a2r2 control-plane protocol.  After the
// 4-byte magic + 21-byte target address, both sides exchange length-prefixed
// control messages (see control.go) and then close their write directions (FIN)
// before opening data streams.  Future protocol extensions add new message
// types without a new magic number.
var agentRouteMagicV2 = []byte{'a', '2', 'r', '2'}

// AgentConn wraps a QUIC connection with the resolved peer and local agent identities.
type AgentConn struct {
	quic.Connection
	// Local is the agent Address that was targeted (agent-route frame, or SNI fallback).
	Local a2al.Address
	// Remote is the connecting peer's Address (from mutual TLS client cert).
	Remote a2al.Address
	// IsRelayed reports whether the underlying ICE path uses a TURN relay on
	// either side. False for direct (host/srflx) and DCUtR punch paths.
	IsRelayed bool
}

// agentEntry is a registered agent in the SNI router.
type agentEntry struct {
	addr           a2al.Address
	priv           ed25519.PrivateKey
	cert           tls.Certificate
	delegationCBOR []byte // non-nil for Phase 3 delegated agents
}

// Host is the Phase 2a runtime.
//
// Identity layering strategy:
//   - DHT and signaling transport use node identity.
//   - QUIC mutual-TLS uses agent identity certificates (including delegated
//     agent cert extensions when applicable).
//   - Each QUIC connection represents a (localAgent, remoteAgent) pair.
//   - The gateway relies on AgentConn.Remote as the authenticated caller AID.
type Host struct {
	cfg     Config
	log     *slog.Logger
	addr    a2al.Address // default (first) agent address
	priv    ed25519.PrivateKey
	mux     *transport.UDPMux
	node    *dht.Node
	sense   *natsense.Sense
	quicTr  *quic.Transport
	qListen *quic.Listener

	// stunProber sends STUN Binding Requests on the shared DHT/QUIC socket
	// (UDPMux) so the reflected port is the real NAT-mapped QUIC port.
	// Nil in split-port mode (cfg.QUICListenAddr != "") until Item 5 is done.
	stunProber *muxSTUNProber

	agentsMu sync.RWMutex
	agents   map[a2al.Address]*agentEntry

	// peerPubkeys caches the Ed25519 identity public key for each peer AID
	// observed via verified incoming mailbox records.  A given AID always maps
	// to the same key (the key is the AID's preimage), so no TTL is needed.
	// Used by SendMailboxForAgent to skip a DHT endpoint lookup when possible.
	peerPubkeys sync.Map // a2al.Address → ed25519.PublicKey

	// punchExpect routes incoming QUIC connections to waiting punchDial goroutines.
	// Key: a2al.Address (expected remote peer), Value: chan quic.Connection.
	// Accept() delivers matching connections here instead of returning them to callers.
	punchExpect sync.Map // a2al.Address → chan quic.Connection

	upnpMu             sync.Mutex
	upnpURL            string
	upnpCleanup        func()
	upnpFailRetryAfter time.Time

	extipMu   sync.Mutex
	extipSnap string    // "ip:port" (STUN) or "ip" (HTTP); empty = not yet resolved
	extipExp  time.Time // cache expiry

	extip6Mu   sync.Mutex
	extip6Snap string    // IPv6 STUN result "ip:port"; empty = not resolved or unavailable
	extip6Exp  time.Time // cache expiry

	iceMu                sync.RWMutex
	bootstrapHubURLs     []string // signal hub URLs from bootstrap/DNS (stable fallback)
	routingHubCandidates []string // signal hub URLs derived from routing table (refreshable)
	activeSignalURLs     []string // currently connected hubs, maintained by ice_listener

	signalStatsMu sync.RWMutex
	signalStats   func() map[string]any

	beaconStatsMu sync.RWMutex
	beaconStats   func() map[string]any

	natProbeMu sync.Mutex // guards RunNATProbe (only one probe at a time)

	// Local IP-family capability, determined once at Host creation.
	// Used by dialTargets to skip addresses the local stack cannot reach.
	hasV4 bool
	hasV6 bool

	punchPool *DHTpunchPool

	iceCache peerICECache
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

	// ICE gathers its own sockets independently of the main QUIC socket (now
	// dual-stack via transport.ListenDualUDP). Both families are active by default.
	if len(cfg.ICENetworkTypes) == 0 {
		cfg.ICENetworkTypes = []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}
	}

	// Create the punch pool before the DHT node so it can be injected into
	// dht.Config. The pool's host reference is set via bind() after the Host
	// struct is fully constructed below.
	hlog := cfg.Logger
	if hlog == nil {
		hlog = slog.Default()
	}
	punchPool := newDHTpunchPool(hlog)

	dhtCfg := dht.Config{
		Keystore: cfg.KeyStore,
		OnObservedAddr: func(reporter a2al.NodeID, wire []byte) {
			sense.Record(reporter, wire)
		},
		RecordAuth:       recordAuthPolicy,
		Logger:           cfg.Logger,
		SeenPeersPath:    cfg.SeenPeersPath,
		PunchTransport:   punchPool,
		LearnedPathFirst: cfg.LearnedPathFirst,
	}

	// listenSocket creates a UDP socket according to the DisableIPv6 flag.
	// DisableIPv6=false (default): dual-stack via transport.ListenDualUDP.
	// DisableIPv6=true: IPv4-only fallback via listenUDP4.
	listenSocket := func(addr string) (net.PacketConn, error) {
		if cfg.DisableIPv6 {
			return listenUDP4(addr)
		}
		return transport.ListenDualUDP(addr)
	}

	var node *dht.Node
	var mux *transport.UDPMux
	var qt *quic.Transport

	if cfg.QUICListenAddr == "" {
		conn, err := listenSocket(cfg.ListenAddr)
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
		// stunProber is initialised after Host is constructed (see below) so
		// it can be stored on h. The field is set immediately after h is built.
	} else {
		dConn, err := listenSocket(cfg.ListenAddr)
		if err != nil {
			return nil, err
		}
		qConn, err := listenSocket(cfg.QUICListenAddr)
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
		cfg:       cfg,
		log:       hlog,
		addr:      myAddr,
		priv:      priv,
		mux:       mux,
		node:      node,
		sense:     sense,
		quicTr:    qt,
		hasV4:     outboundIPv4() != nil,
		hasV6:     !cfg.DisableIPv6 && outboundIPv6() != nil,
		punchPool: punchPool,
		agents: map[a2al.Address]*agentEntry{
			myAddr: {addr: myAddr, priv: priv, cert: defaultCert},
		},
	}
	h.iceCache.init()
	punchPool.bind(h)
	// Initialise same-socket STUN prober when DHT and QUIC share one socket.
	// In split-port mode (QUICListenAddr != "") mux is nil; prober stays nil.
	if mux != nil {
		h.stunProber = newMuxSTUNProber(mux)
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
		h.log.Warn("RegisterDelegatedAgent: overwriting existing entry", "aid", addr.String())
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

func (h *Host) Node() *dht.Node             { return h.node }
func (h *Host) Sense() *natsense.Sense      { return h.sense }
func (h *Host) Address() a2al.Address       { return h.addr }
func (h *Host) DHTpunchPool() *DHTpunchPool { return h.punchPool }

func (h *Host) DHTLocalAddr() *net.UDPAddr {
	return h.node.LocalAddr().(*net.UDPAddr)
}

func (h *Host) QUICLocalAddr() *net.UDPAddr {
	return h.quicTr.Conn.LocalAddr().(*net.UDPAddr)
}

func (h *Host) LocalUDPAddr() *net.UDPAddr { return h.DHTLocalAddr() }

func (h *Host) ObserveFromPeers(ctx context.Context, seeds []net.Addr) {
	var wg sync.WaitGroup
	for _, s := range seeds {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			pi, err := h.node.PingIdentity(ctx, s)
			if err != nil || len(pi.ObservedWire) == 0 {
				return
			}
			h.sense.Record(pi.NodeID, pi.ObservedWire)
		}()
	}
	wg.Wait()
}

// ObserveFromRouting samples current routing-table candidates and performs
// passive observed_addr collection from them.
func (h *Host) ObserveFromRouting(ctx context.Context, n int) int {
	if n <= 0 {
		n = 8
	}
	seeds := h.node.BootstrapCandidateAddrs(n)
	if len(seeds) == 0 {
		return 0
	}
	h.ObserveFromPeers(ctx, seeds)
	return len(seeds)
}

// RunNATProbe performs an AutoNAT-style active reachability test for both IP
// families. At most one probe runs at a time (TryLock); concurrent callers
// return immediately.
//
// IPv4 classification:
//
//	QUIC bind IP is a public v4 WAN address   → sense.RecordV4BindPublic(true); skip echo probe
//	echo received from ≥1 v4 candidate        → sense.RecordV4ProbeResult(true)
//	no echo despite known v4 external address → sense.RecordV4ProbeResult(false)
//
// IPv6 classification:
//
//	no GUA interface address                  → sense.RecordV6GUABind(false); v6 probe skipped
//	GUA present; echo from ≥1 v6 candidate   → sense.RecordV6ProbeResult(true)
//	GUA present; no echo                      → sense.RecordV6ProbeResult(false)
func (h *Host) RunNATProbe(ctx context.Context) {
	if !h.natProbeMu.TryLock() {
		return // another probe is already running
	}
	defer h.natProbeMu.Unlock()

	h.runNATProbeV4(ctx)
	h.runNATProbeV6(ctx)
}

// runNATProbeV4 runs the IPv4 track of RunNATProbe.
func (h *Host) runNATProbeV4(ctx context.Context) {
	// ① Detect public v4 bind. QUICLocalAddr is typically [::] on dual-stack
	// hosts, so this branch fires only on hosts with a routable v4 bind address.
	if qa := h.QUICLocalAddr(); qa != nil && qa.IP.To4() != nil && isPlausibleWANIP(qa.IP) {
		h.sense.RecordV4BindPublic(true)
		h.log.Debug("nat probe v4: public bind", "ip", qa.IP)
		return // directly reachable; no inbound echo probe needed
	}
	h.sense.RecordV4BindPublic(false)

	// ② Claimed external v4 address: natsense consensus preferred, STUN fallback.
	claimedWire, ok := h.sense.TrustedWireV4()
	if !ok {
		sctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		stunIP, stunPort := probeSTUNViaMux(sctx, h.stunProber, "udp4")
		cancel()
		if stunIP != nil && isPlausibleWANIP(stunIP) {
			if b, err := protocol.FormatObservedUDP(stunIP, stunPort); err == nil {
				claimedWire = b
			}
		}
	}
	if len(claimedWire) == 0 {
		h.log.Debug("nat probe v4: no claimed external address; skipping")
		return
	}

	// ③ Select up to 3 v4 candidates from the routing table.
	candidates := h.selectNATProbeTargets(3)
	if len(candidates) == 0 {
		h.log.Debug("nat probe v4: no public-IP candidates in routing table; skipping")
		return
	}

	// ④ Probe concurrently; ≥1 successful echo → reachable.
	type result struct{ ok bool }
	results := make(chan result, len(candidates))
	for _, addr := range candidates {
		addr := addr
		go func() {
			pCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ok, _ := h.node.SendNATProbeReq(pCtx, addr, claimedWire)
			results <- result{ok}
		}()
	}
	var reachable bool
	for range candidates {
		if r := <-results; r.ok {
			reachable = true
		}
	}
	h.sense.RecordV4ProbeResult(reachable)
	h.log.Debug("nat probe v4 done", "reachable", reachable, "candidates", len(candidates))
}

// runNATProbeV6 runs the IPv6 track of RunNATProbe.
// It is a no-op on IPv4-only hosts (no GUA interface address).
func (h *Host) runNATProbeV6(ctx context.Context) {
	// ① Detect GUA IPv6 interface address via an outbound route probe.
	v6IP := outboundIPv6()
	hasGUA := v6IP != nil && isPlausibleWANIP(v6IP)
	h.sense.RecordV6GUABind(hasGUA)
	if !hasGUA {
		return // IPv4-only (or v6 unreachable); v6 track is a no-op
	}

	// ② Claimed external v6 address: natsense consensus preferred, STUN fallback.
	claimedWire, ok := h.sense.TrustedWireV6()
	if !ok {
		sctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		stunIP, stunPort := probeSTUNViaMux(sctx, h.stunProber, "udp6")
		cancel()
		if stunIP != nil && isPlausibleWANIP(stunIP) {
			if b, err := protocol.FormatObservedUDP(stunIP, stunPort); err == nil {
				claimedWire = b
			}
		}
	}
	if len(claimedWire) == 0 {
		h.log.Debug("nat probe v6: no claimed external address; skipping")
		return
	}

	// ③ Select up to 3 v6 GUA candidates from the routing table.
	candidates := h.selectNATProbeTargetsV6(3)
	if len(candidates) == 0 {
		h.log.Debug("nat probe v6: no GUA-v6 candidates in routing table; skipping")
		return
	}

	// ④ Probe concurrently; ≥1 successful echo → directly reachable v6.
	type result struct{ ok bool }
	results := make(chan result, len(candidates))
	for _, addr := range candidates {
		addr := addr
		go func() {
			pCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ok, _ := h.node.SendNATProbeReq(pCtx, addr, claimedWire)
			results <- result{ok}
		}()
	}
	var reachable bool
	for range candidates {
		if r := <-results; r.ok {
			reachable = true
		}
	}
	h.sense.RecordV6ProbeResult(reachable)
	h.log.Debug("nat probe v6 done", "reachable", reachable, "candidates", len(candidates))
}

// InvalidateNetworkCaches clears short-lived external-network caches so
// subsequent endpoint building uses fresh probes after network changes.
func (h *Host) InvalidateNetworkCaches() {
	h.extipMu.Lock()
	h.extipSnap = ""
	h.extipExp = time.Time{}
	h.extipMu.Unlock()
	h.extip6Mu.Lock()
	h.extip6Snap = ""
	h.extip6Exp = time.Time{}
	h.extip6Mu.Unlock()
	h.sense.ClearProbeResult()
	h.sense.InvalidateObservations()
	h.node.ClearReachabilityHints()
}

// selectNATProbeTargets returns up to n UDP addresses of routing-table peers
// with public WAN IPv4 addresses. IPv6 addresses are excluded so that the v4
// probe track sends its claimed v4 wire address only to v4 reachable peers.
func (h *Host) selectNATProbeTargets(n int) []net.Addr {
	all := h.node.BootstrapCandidateAddrs(n * 5)
	var out []net.Addr
	for _, a := range all {
		udp, ok := a.(*net.UDPAddr)
		if !ok || udp.IP.To4() == nil || !isPlausibleWANIP(udp.IP) {
			continue
		}
		out = append(out, a)
		if len(out) >= n {
			break
		}
	}
	return out
}

// selectNATProbeTargetsV6 returns up to n UDP addresses of routing-table peers
// with public WAN IPv6 (GUA) addresses for the v6 probe track.
func (h *Host) selectNATProbeTargetsV6(n int) []net.Addr {
	all := h.node.BootstrapCandidateAddrs(n * 5)
	var out []net.Addr
	for _, a := range all {
		udp, ok := a.(*net.UDPAddr)
		if !ok || udp.IP.To4() != nil || !isPlausibleWANIP(udp.IP) {
			continue
		}
		out = append(out, a)
		if len(out) >= n {
			break
		}
	}
	return out
}

// BuildEndpointPayload builds ordered, deduplicated quic:// candidates (Phase 2b).
// UPnP discovery and external IP probing (STUN + HTTP) run concurrently.
func (h *Host) BuildEndpointPayload(ctx context.Context) (protocol.EndpointPayload, error) {
	t0 := time.Now()
	upCh := make(chan string, 1)
	extCh := make(chan string, 1)
	ext6Ch := make(chan string, 1)
	go func() { upCh <- h.ensureUPnP(ctx) }()
	go func() { extCh <- h.ensureExternalIP(ctx) }()
	go func() { ext6Ch <- h.ensureExternalIPv6(ctx) }()
	up := <-upCh
	ext := <-extCh
	ext6 := <-ext6Ch
	if elapsed := time.Since(t0).Truncate(time.Millisecond); elapsed > 0 {
		h.log.Debug("endpoint probe done", "elapsed", elapsed, "ext_ip_v4", ext, "ext_ip_v6", ext6, "upnp", up)
	}

	// Inform the DHT node of our public IPv4 so it can detect NAT hairpin peers
	// (nodes behind the same NAT share the same public IP).  IPv6 GUA nodes are
	// directly reachable without hairpinning, so v6 hairpin detection is
	// intentionally skipped. The v6 IP is stored separately for well-known-node self-identify.
	if ext != "" {
		ipStr := ext
		if host, _, err := net.SplitHostPort(ext); err == nil {
			ipStr = host
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			h.node.SetSelfExtIP(ip)
		}
	}
	if ext6 != "" {
		ipStr := ext6
		if host, _, err := net.SplitHostPort(ext6); err == nil {
			ipStr = host
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			h.node.SetSelfExtIPv6(ip)
		}
	}

	eps, err := h.orderedQUICEndpointStrings(ext, ext6, up) // ext=IPv4, ext6=IPv6, up=UPnP
	if err != nil {
		return protocol.EndpointPayload{}, err
	}

	// Signal URLs: publish only live connections (or explicit config).
	// turns[] is intentionally not published: callee-pays TURN relay addresses are
	// exchanged via trickle ICE during sessions, not stored in the DHT.
	signals := h.publishSignalURLs()
	var signal string
	if len(signals) > 0 {
		signal = signals[0]
	}
	return protocol.EndpointPayload{
		Endpoints: eps,
		NatType:   h.sense.PublishNatType(),
		Signal:    signal,
		Signals:   signals,
	}, nil
}

// effectiveICESignalURLs returns the ordered candidate list for ice_listener to
// attempt connections to. Priority: ICESignalURLs config > ICESignalURL config >
// routing-derived candidates > bootstrap-derived candidates.
// This list drives WHICH hubs to try, not what to publish.
func (h *Host) effectiveICESignalURLs() []string {
	h.iceMu.RLock()
	defer h.iceMu.RUnlock()
	if len(h.cfg.ICESignalURLs) > 0 {
		return h.cfg.ICESignalURLs
	}
	if h.cfg.ICESignalURL != "" {
		return []string{h.cfg.ICESignalURL}
	}
	// Merge routing candidates (preferred) and bootstrap URLs (fallback), dedup.
	seen := make(map[string]struct{})
	out := make([]string, 0, len(h.routingHubCandidates)+len(h.bootstrapHubURLs))
	for _, u := range h.routingHubCandidates {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	for _, u := range h.bootstrapHubURLs {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

// publishSignalURLs returns the signal hub URLs to include in endpoint records.
// For explicitly configured URLs the operator vouches for them; for bootstrap-derived
// URLs only hubs with live connections are published, avoiding stale DHT entries.
func (h *Host) publishSignalURLs() []string {
	h.iceMu.RLock()
	defer h.iceMu.RUnlock()
	if len(h.cfg.ICESignalURLs) > 0 {
		return h.cfg.ICESignalURLs
	}
	if h.cfg.ICESignalURL != "" {
		return []string{h.cfg.ICESignalURL}
	}
	if len(h.activeSignalURLs) > 0 {
		out := make([]string, len(h.activeSignalURLs))
		copy(out, h.activeSignalURLs)
		return out
	}
	return nil
}

func (h *Host) effectiveICESignalBase() string {
	urls := h.effectiveICESignalURLs()
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// EffectiveICESignalBase returns the first hub URL from the effective candidate
// list (config > routing-derived > bootstrap-derived). Used by callers that need
// a single hub URL for an outbound ICE session.
func (h *Host) EffectiveICESignalBase() string {
	return h.effectiveICESignalBase()
}

// EffectiveICESignalURLs returns the full ordered list of ICE signaling base URLs.
// Callee subscribers should open one /signal connection per URL.
// Callers should try each URL in order until one succeeds.
func (h *Host) EffectiveICESignalURLs() []string {
	return h.effectiveICESignalURLs()
}

// SetBootstrapHubURLs sets signal hub URLs derived from bootstrap/DNS infrastructure.
// These serve as a stable fallback when routing-table candidates are unavailable.
// Explicit config (ICESignalURLs / ICESignalURL) always wins and is not overwritten.
func (h *Host) SetBootstrapHubURLs(urls []string) {
	h.iceMu.Lock()
	defer h.iceMu.Unlock()
	if len(h.cfg.ICESignalURLs) > 0 || h.cfg.ICESignalURL != "" {
		return
	}
	h.bootstrapHubURLs = urls
}

// SetRoutingHubCandidates sets signal hub candidates derived from the routing table.
// These are preferred over bootstrap URLs and are refreshed periodically.
// Explicit config (ICESignalURLs / ICESignalURL) always wins and is not overwritten.
func (h *Host) SetRoutingHubCandidates(urls []string) {
	h.iceMu.Lock()
	defer h.iceMu.Unlock()
	if len(h.cfg.ICESignalURLs) > 0 || h.cfg.ICESignalURL != "" {
		return
	}
	h.routingHubCandidates = urls
}

// RoutingHubCandidates returns the current routing-table-derived hub candidate list.
func (h *Host) RoutingHubCandidates() []string {
	h.iceMu.RLock()
	defer h.iceMu.RUnlock()
	out := make([]string, len(h.routingHubCandidates))
	copy(out, h.routingHubCandidates)
	return out
}

// DeriveRoutingHubURLs derives signal hub ws:// URLs from the DHT routing table,
// selecting peers with high inbound TCP reachability (NATFullCone or v6 GUA).
// Returns up to max candidates with bucket-index diversity.
func (h *Host) DeriveRoutingHubURLs(max int) []string {
	addrs := h.node.PublicHubCandidates(max)
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		udp, ok := a.(*net.UDPAddr)
		if !ok || udp.Port == 0 {
			continue
		}
		u, err := signaling.DeriveSignalBaseFromHostPort(udp.String())
		if err != nil {
			continue
		}
		out = append(out, u)
	}
	return out
}

// SetActiveSignalURLs records the set of signal hub URLs with live connections.
// Called by ice_listener when the active set changes; BuildEndpointPayload uses
// this list (instead of all candidates) to avoid publishing stale hub addresses.
func (h *Host) SetActiveSignalURLs(urls []string) {
	h.iceMu.Lock()
	h.activeSignalURLs = urls
	h.iceMu.Unlock()
}

// ActiveSignalURLs returns a snapshot of the currently connected signal hub
// URLs. Returns nil when no hub is connected.
func (h *Host) ActiveSignalURLs() []string {
	h.iceMu.RLock()
	defer h.iceMu.RUnlock()
	if len(h.activeSignalURLs) == 0 {
		return nil
	}
	out := make([]string, len(h.activeSignalURLs))
	copy(out, h.activeSignalURLs)
	return out
}

// SetSignalStatsProvider merges hub stats into GET /debug/stats under "signal".
func (h *Host) SetSignalStatsProvider(f func() map[string]any) {
	h.signalStatsMu.Lock()
	h.signalStats = f
	h.signalStatsMu.Unlock()
}

// SetBeaconStatsProvider registers fn to supply optional extra key-value fields merged into
// GET /debug/stats (e.g. metrics for the high-capacity auxiliary DHT path). Omitted when fn
// is nil; fields omitted when the callback returns nil or an empty map.
func (h *Host) SetBeaconStatsProvider(fn func() map[string]any) {
	h.beaconStatsMu.Lock()
	h.beaconStats = fn
	h.beaconStatsMu.Unlock()
}

// SetDHTPushHandler registers fn as the handler for incoming MsgDHTPush messages
// (oneShot push from DHT nodes). fn(key, record) returns true when the record is
// new, which causes the ACK to renew the subscription for future deliveries.
// Works in both single-port (UDPMux) and dual-port modes.
func (h *Host) SetDHTPushHandler(fn func(key a2al.NodeID, rec protocol.SignedRecord) bool) {
	h.node.SetPushHandler(fn)
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

	// STUN probe: prefer same-socket prober (port reflects true QUIC NAT mapping);
	// fall back to ephemeral-socket probe when prober is unavailable (split-port mode).
	sctx, scancel := context.WithTimeout(ctx, 3*time.Second)
	stunIP, stunPort := probeSTUNViaMux(sctx, h.stunProber, "udp4")
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

// ensureExternalIPv6 returns a cached or freshly probed IPv6 external address
// (from STUN, "ip:port" format). Returns "" on v6-only machines without a
// global unicast address, or when dual-stack is disabled.
func (h *Host) ensureExternalIPv6(ctx context.Context) string {
	if h.cfg.DisableIPv6 {
		return ""
	}
	h.extip6Mu.Lock()
	// Use expiry-only check so negative results (snap=="") are also served from
	// cache — prevents repeated STUN probes on IPv4-only machines.
	if !h.extip6Exp.IsZero() && time.Now().Before(h.extip6Exp) {
		snap := h.extip6Snap
		h.extip6Mu.Unlock()
		return snap
	}
	h.extip6Mu.Unlock()

	sctx, scancel := context.WithTimeout(ctx, 3*time.Second)
	stunIP, stunPort := probeSTUNViaMux(sctx, h.stunProber, "udp6")
	scancel()

	var snap string
	if stunIP != nil && isPlausibleWANIP(stunIP) {
		snap = net.JoinHostPort(stunIP.String(), strconv.Itoa(int(stunPort)))
	}

	h.extip6Mu.Lock()
	h.extip6Snap = snap // cache negative result too (avoids repeated probes on v4-only machines)
	h.extip6Exp = time.Now().Add(extipCacheTTL)
	h.extip6Mu.Unlock()
	return snap
}

// ensureUPnP attempts IGD port mapping via UPnP. Returns the mapped quic:// URL,
// or empty when UPnP is disabled or unavailable.
//
// IPv6 note: UPnP IGD is an IPv4 NAT mechanism. Nodes with a global IPv6 address
// are directly reachable and do not need port mapping — this function is skipped
// implicitly because their public IP is collected via natsense/STUN instead.
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

// PublishEndpointBuilt publishes the node endpoint using a pre-built EndpointPayload.
// Use this when the payload has already been constructed (e.g. to avoid a redundant probe).
func (h *Host) PublishEndpointBuilt(ctx context.Context, ep protocol.EndpointPayload, seq uint64, ttl uint32) error {
	return h.publishEndpointForAgentWithPayload(ctx, h.addr, ep, seq, ttl)
}

// PublishEndpointForAgent publishes an endpoint record signed by the given registered agent.
// For Phase 3 delegated agents (registered via RegisterDelegatedAgent), the record embeds
// the DelegationProof so DHT nodes can verify the operational key's authority.
func (h *Host) PublishEndpointForAgent(ctx context.Context, agentAddr a2al.Address, seq uint64, ttl uint32) error {
	ep, err := h.BuildEndpointPayload(ctx)
	if err != nil {
		return err
	}
	return h.publishEndpointForAgentWithPayload(ctx, agentAddr, ep, seq, ttl)
}

// publishEndpointForAgentWithPayload signs and stores a pre-built EndpointPayload.
func (h *Host) publishEndpointForAgentWithPayload(ctx context.Context, agentAddr a2al.Address, ep protocol.EndpointPayload, seq uint64, ttl uint32) error {
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	now := time.Now().Truncate(time.Second)
	var (
		rec protocol.SignedRecord
		err error
	)
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
	cert, err := h.defaultAgentCert()
	if err != nil {
		return nil, err
	}
	return h.dialAndAgentRoute(ctx, cert, expectRemote, udpAddr)
}

// doDialerControlStream opens Stream 0, writes the a2r2 route frame and dialer
// control messages, then returns immediately.  Reading the acceptor's response
// (ObservedAddr / AgentInfo) happens in a background goroutine so that the
// caller can start opening data streams without waiting for the exchange.
//
// Only stream-open and route-frame failures are fatal; control-message errors
// are logged and ignored — the connection is always usable without the bonus.
func (h *Host) doDialerControlStream(ctx context.Context, conn quic.Connection, expectRemote a2al.Address) error {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("a2al/host: open control stream: %w", err)
	}

	// Write route frame — acceptor needs this to resolve the target AID.
	var frame [25]byte
	copy(frame[:4], agentRouteMagicV2)
	copy(frame[4:], expectRemote[:])
	if _, err := str.Write(frame[:]); err != nil {
		return fmt.Errorf("a2al/host: write route frame: %w", err)
	}

	// Snapshot the max topic seq held locally; fast in-memory scan.
	// RecTypeTopic (0x10) is the only topic variant in current use; if future
	// variants (0x11–0x1F) are introduced, switch to a category-based scan.
	var heldSeq uint64
	for _, r := range h.node.LocalStoreGetByAddress(expectRemote, protocol.RecTypeTopic) {
		if r.Seq > heldSeq {
			heldSeq = r.Seq
		}
	}

	// The rest of the exchange is bonus: send our hint, read acceptor's reply.
	// Run in a goroutine so the caller is not blocked on network round-trips.
	// The goroutine terminates naturally when the stream closes (connection gone).
	go func() {
		if err := sendDialerMsgs(str, expectRemote, heldSeq); err != nil {
			h.log.Debug("control: send dialer msgs", "remote_aid", expectRemote, "err", err)
			return
		}
		observedWire, receivedRecs, err := readAcceptorMsgs(str)
		if err != nil {
			h.log.Debug("control: read acceptor msgs", "remote_aid", expectRemote, "err", err)
		}
		if len(observedWire) > 0 {
			h.sense.Record(a2al.NodeIDFromAddress(expectRemote), observedWire)
		}
		for _, rec := range receivedRecs {
			te, perr := protocol.ParseTopicRecord(rec)
			if perr != nil {
				continue
			}
			_ = h.node.LocalStorePut(protocol.TopicNodeID(te.Topic), rec)
		}
	}()

	return nil
}

// controlStreamError wraps a failure that occurred after the QUIC+TLS handshake
// succeeded but during Stream 0 control exchange.  The network path itself was
// reachable; callers (e.g. connectHappy) must not report this as a transport
// failure to the DHT health subsystem.
type controlStreamError struct{ cause error }

func (e *controlStreamError) Error() string { return e.cause.Error() }
func (e *controlStreamError) Unwrap() error { return e.cause }

func (h *Host) dialAndAgentRoute(ctx context.Context, localCert tls.Certificate, expectRemote a2al.Address, udpAddr *net.UDPAddr) (quic.Connection, error) {
	cliTLS, err := quicClientTLSWithCert(localCert, expectRemote)
	if err != nil {
		return nil, err
	}
	h.log.Debug("quic dial", "src", h.quicTr.Conn.LocalAddr(), "dst", udpAddr, "remote_aid", expectRemote)
	t0 := time.Now()
	conn, err := h.quicTr.Dial(ctx, udpAddr, cliTLS, defaultQUICConfig())
	if err != nil {
		return nil, err
	}
	// Capture RTT immediately after the QUIC+TLS handshake, before opening
	// Stream 0, so the value reflects network latency only.
	handshakeRTT := time.Since(t0)
	if err := h.doDialerControlStream(ctx, conn, expectRemote); err != nil {
		_ = conn.CloseWithError(1, "control stream failed")
		return nil, &controlStreamError{cause: err}
	}
	// Notify the DHT health subsystem of the verified outbound connection.
	// conn.RemoteAddr() is the actual NAT-mapped address.
	if udpRemote, ok := conn.RemoteAddr().(*net.UDPAddr); ok && udpRemote != nil {
		h.node.NotePeerDialSuccess(a2al.NodeIDFromAddress(expectRemote), udpRemote, handshakeRTT)
	}
	return conn, nil
}

func (h *Host) defaultAgentCert() (tls.Certificate, error) {
	h.agentsMu.RLock()
	ag, ok := h.agents[h.addr]
	h.agentsMu.RUnlock()
	if !ok {
		return tls.Certificate{}, fmt.Errorf("a2al/host: unknown agent %s", h.addr)
	}
	return ag.cert, nil
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
	for {
		conn, err := h.qListen.Accept(ctx)
		if err != nil {
			return nil, err
		}
		// Route incoming punch connections to the waiting punchDial goroutine.
		state := conn.ConnectionState().TLS
		if remote, rErr := peerAddrFromTLSState(state); rErr == nil {
			if v, ok := h.punchExpect.Load(remote); ok {
			// Notify the DHT subsystem of the confirmed punch path so health
			// counters are updated alongside the peer-face address cache.
			if udpRemote, ok2 := conn.RemoteAddr().(*net.UDPAddr); ok2 && udpRemote != nil {
				h.node.NotePeerDialSuccess(a2al.NodeIDFromAddress(remote), udpRemote, 0)
			}
				ch := v.(chan quic.Connection)
				select {
				case ch <- conn:
				default:
					_ = conn.CloseWithError(0, "punch: expect queue full")
				}
				continue
			}
		}
		return h.agentConnFromQUIC(ctx, conn, h.addr)
	}
}

func (h *Host) agentConnFromQUIC(ctx context.Context, conn quic.Connection, fallbackLocal a2al.Address) (*AgentConn, error) {
	ac := &AgentConn{Connection: conn, Local: fallbackLocal}

	state := conn.ConnectionState().TLS
	if remote, err := peerAddrFromTLSState(state); err == nil {
		ac.Remote = remote
	}

	// Try agent-route control stream (canonical, a2r1 or a2r2).
	if target, err := h.doAcceptorControlStream(ctx, conn); err == nil {
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

	// Notify the DHT subsystem of the verified inbound connection.
	// ac.Remote is populated from the TLS certificate; conn.RemoteAddr() is the
	// actual source address observed by the OS.  rtt=0 because we have no
	// handshake timing on the acceptor side.
	if ac.Remote != (a2al.Address{}) {
		if udpRemote, ok := conn.RemoteAddr().(*net.UDPAddr); ok && udpRemote != nil {
			h.node.NotePeerDialSuccess(a2al.NodeIDFromAddress(ac.Remote), udpRemote, 0)
		}
	}
	return ac, nil
}

// doAcceptorControlStream accepts Stream 0, reads the route frame, and (for
// a2r2 connections) runs the control message exchange.  Side effects:
//   - Sends ObservedAddr (the dialer's public UDP address as seen by this node).
//   - Sends AgentInfo records for the target agent if the dialer's held_seq is
//     behind the local store, so the dialer's cache is refreshed transparently.
//
// Supports both a2r1 (legacy, no control exchange) and a2r2 (full exchange).
// Unknown magic bytes are rejected; the caller falls back to SNI routing.
func (h *Host) doAcceptorControlStream(ctx context.Context, conn quic.Connection) (a2al.Address, error) {
	str, err := conn.AcceptStream(ctx)
	if err != nil {
		return a2al.Address{}, err
	}

	// Read magic (4 B) + target address (21 B).
	var header [25]byte
	if _, err := io.ReadFull(str, header[:]); err != nil {
		return a2al.Address{}, err
	}
	magic := header[:4]
	var addr a2al.Address
	copy(addr[:], header[4:])

	switch string(magic) {
	case string(agentRouteMagic): // a2r1: legacy — no control exchange
		return addr, nil

	case string(agentRouteMagicV2): // a2r2: full control exchange

		// Read dialer's control messages (blocks until dialer FIN).
		heldSeq, rerr := readDialerMsgs(str)
		if rerr != nil {
			h.log.Debug("control: read dialer msgs", "err", rerr)
			heldSeq = 0 // assume dialer has nothing; push all records
		}

		// Look up fresh topic records for the target agent in the local store.
		// See dialer-side comment: only 0x10 is in use; extend when 0x11–0x1F land.
		localRecs := h.node.LocalStoreGetByAddress(addr, protocol.RecTypeTopic)

		// Send acceptor's control messages and FIN.
		if serr := sendAcceptorMsgs(str, conn.RemoteAddr(), localRecs, heldSeq); serr != nil {
			h.log.Debug("control: send acceptor msgs", "err", serr)
		}

		return addr, nil

	default:
		return a2al.Address{}, errors.New("a2al/host: bad agent-route magic")
	}
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

// outboundIPv4 returns the preferred IPv4 outbound address without sending any
// packets, by connecting a UDP socket to a public IPv4 address and reading the
// local address the OS assigned.
func outboundIPv4() net.IP {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

// outboundIPv6 returns the preferred IPv6 outbound address without sending any
// packets, by connecting a UDP socket to a public IPv6 address and reading the
// local address the OS assigned. Returns nil if the host has no IPv6
// connectivity (ENETUNREACH) or no global unicast outbound route.
func outboundIPv6() net.IP {
	conn, err := net.Dial("udp6", "[2001:4860:4860::8888]:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	// Discard link-local and loopback — we want only GUA / ULA.
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return nil
	}
	return ip
}

// listenUDP4 resolves addr as IPv4 UDP and opens an IPv4-only socket.
//
// This is the DisableIPv6=true fallback path. Under normal operation New()
// uses transport.ListenDualUDP instead, which binds a dual-stack socket on
// Linux/macOS and an IPv4+IPv6 socket pair on Windows. listenUDP4 is kept as
// an emergency escape hatch for deployments where dual-stack causes problems.
func listenUDP4(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp4", a)
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
//
// Sovereign records: DHT key must equal NodeID(sr.Address); signer must own or hold
// a valid delegation for that address.
// Topic records: signer must own or hold a valid delegation for sr.Address (the
// registering agent's AID); DHT key binding is not checked (topic key is content-derived).
// Mailbox records: DHT key is NodeID(recipient), which differs from sr.Address (sender AID),
// so key binding is skipped — but the signer must still own or hold a valid delegation for
// sr.Address (the sender AID). This prevents sender identity spoofing.
func recordAuthPolicy(key a2al.NodeID, sr protocol.SignedRecord, now time.Time) error {
	cat := protocol.RecordCategory(sr.RecType)

	var recAddr a2al.Address
	copy(recAddr[:], sr.Address)

	// Sovereign-only: DHT key must equal NodeID(sr.Address).
	if cat == protocol.CategorySovereign {
		if key != a2al.NodeIDFromAddress(recAddr) {
			return errors.New("a2al/host: sovereign record DHT key mismatch")
		}
	}

	// Shared authority check (Sovereign + Topic + Mailbox): signing key must be authorized for sr.Address.
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
