// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package host is the Phase 2a SDK: DHT + QUIC, nat-sense, Publish/Resolve/Connect/Accept.
//
// When Config.QUICListenAddr is empty, DHT and QUIC share one UDP port via UDPMux (spec target; still maturing).
// When QUICListenAddr is set (e.g. ":5002" or "127.0.0.1:0"), QUIC uses a separate socket — recommended for production until mux is hardened.
package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
	// QUICListenAddr, if non-empty, is a separate UDP bind for QUIC. Use this for reliable stacks (tests, production)
	// until single-port UDPMux is fully validated on all platforms.
	QUICListenAddr string
	PrivateKey     ed25519.PrivateKey
	MinObservedPeers int
	FallbackHost     string
}

// Host is the Phase 2a runtime.
type Host struct {
	cfg     Config
	addr    a2al.Address
	priv    ed25519.PrivateKey
	mux     *transport.UDPMux // nil when QUIC uses a separate socket
	node    *dht.Node
	sense   *natsense.Sense
	quicTr  *quic.Transport
	qListen *quic.Listener
}

// New listens on UDP and starts the DHT node and QUIC listener.
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

	dhtUDP, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
	if err != nil {
		return nil, err
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
		node, err = dht.NewNode(dht.Config{Transport: mux.DHTTransport(), Keystore: cfg.KeyStore})
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
		node, err = dht.NewNode(dht.Config{Transport: transport.NewUDPTransport(dConn), Keystore: cfg.KeyStore})
		if err != nil {
			_ = dConn.Close()
			_ = qConn.Close()
			return nil, err
		}
		qt = &quic.Transport{Conn: qConn}
	}

	srvTLS, err := quicServerTLS(priv)
	if err != nil {
		if mux != nil {
			_ = mux.Close()
		} else {
			_ = node.Close()
		}
		return nil, err
	}
	qListen, err := qt.Listen(srvTLS, defaultQUICConfig())
	if err != nil {
		if mux != nil {
			_ = mux.Close()
		} else {
			_ = node.Close()
		}
		return nil, err
	}

	min := cfg.MinObservedPeers
	if min == 0 {
		min = 3
	}
	h := &Host{
		cfg:     cfg,
		addr:    myAddr,
		priv:    priv,
		mux:     mux,
		node:    node,
		sense:   natsense.NewSense(min),
		quicTr:  qt,
		qListen: qListen,
	}
	node.Start()
	return h, nil
}

func (h *Host) Node() *dht.Node { return h.node }
func (h *Host) Sense() *natsense.Sense { return h.sense }
func (h *Host) Address() a2al.Address { return h.addr }

// DHTLocalAddr is the DHT/control UDP bind address (bootstrap, PING, STORE).
func (h *Host) DHTLocalAddr() *net.UDPAddr {
	return h.node.LocalAddr().(*net.UDPAddr)
}

// QUICLocalAddr is the UDP address peers should use for QUIC Connect (published in endpoint records).
func (h *Host) QUICLocalAddr() *net.UDPAddr {
	return h.quicTr.Conn.LocalAddr().(*net.UDPAddr)
}

// LocalUDPAddr returns the DHT UDP address (same as DHTLocalAddr). For QUIC port when split, use QUICLocalAddr.
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

// BuildEndpointPayload builds udp:// for QUIC reachability (QUICLocalAddr port).
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
		return protocol.EndpointPayload{}, errors.New("a2al/host: no advertise host (set FallbackHost, MinObservedPeers=1 with seeds, or bind a specific IP)")
	}
	ep := "udp://" + net.JoinHostPort(hostStr, strconv.Itoa(port))
	return protocol.EndpointPayload{
		Endpoints: []string{ep},
		NatType:   protocol.NATUnknown,
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

func (h *Host) Connect(ctx context.Context, expectRemote a2al.Address, udpAddr *net.UDPAddr) (quic.Connection, error) {
	if h.mux != nil {
		h.mux.MarkQUICPeer(udpAddr)
	}
	cliTLS, err := quicClientTLS(h.priv, expectRemote)
	if err != nil {
		if h.mux != nil {
			h.mux.UnmarkQUICPeer(udpAddr)
		}
		return nil, err
	}
	c, err := h.quicTr.Dial(ctx, udpAddr, cliTLS, defaultQUICConfig())
	if err != nil {
		if h.mux != nil {
			h.mux.UnmarkQUICPeer(udpAddr)
		}
		return nil, err
	}
	return c, nil
}

func (h *Host) Accept(ctx context.Context) (quic.Connection, error) {
	c, err := h.qListen.Accept(ctx)
	if err != nil {
		return nil, err
	}
	if h.mux != nil {
		h.mux.MarkQUICPeer(c.RemoteAddr())
	}
	return c, nil
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

func FirstUDPAddr(er *protocol.EndpointRecord) (*net.UDPAddr, error) {
	if er == nil {
		return nil, errors.New("a2al/host: nil endpoint record")
	}
	for _, e := range er.Endpoints {
		u, err := url.Parse(e)
		if err != nil || u.Scheme != "udp" || u.Host == "" {
			continue
		}
		return net.ResolveUDPAddr("udp4", u.Host)
	}
	return nil, errors.New("a2al/host: no udp endpoint in record")
}
