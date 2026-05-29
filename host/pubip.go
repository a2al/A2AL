// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al/transport"
)

// stunServers are queried for the external UDP mapping using STUN Binding Requests
// (RFC 5389). All entries have both A and AAAA records, so the same list is used
// for IPv4 probes (network="udp4") and IPv6 probes (network="udp6").
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// ---------------------------------------------------------------------------
// Same-socket STUN: probe the shared DHT/QUIC UDP socket instead of an
// ephemeral temporary socket. This makes the returned port directly useful
// because NAT maps ports per (local-socket, remote-addr) pair.
// ---------------------------------------------------------------------------

// stunPendingEntry holds the reply channel for one in-flight STUN binding request.
type stunPendingEntry struct {
	ch    chan stunResult
	txID  [12]byte
}

type stunResult struct {
	ip   net.IP
	port uint16
}

// muxSTUNProber sends STUN Binding Requests on a UDPMux (shared socket) and
// routes the responses back via a SetPacketFilter hook.
type muxSTUNProber struct {
	mux     *transport.UDPMux
	mu      sync.Mutex
	pending map[[12]byte]chan stunResult
}

func newMuxSTUNProber(mux *transport.UDPMux) *muxSTUNProber {
	p := &muxSTUNProber{
		mux:     mux,
		pending: make(map[[12]byte]chan stunResult),
	}
	mux.SetPacketFilter(p.intercept)
	return p
}

// intercept is installed as the UDPMux packet filter.  It checks whether the
// incoming packet looks like a STUN message (magic cookie present).
//
// Any valid STUN packet is consumed here to prevent spurious noise reaching the
// DHT decoder.  If the transaction ID matches a pending probe request the result
// is forwarded to the waiting goroutine; otherwise the packet is silently dropped
// (it may be a stale response or an unsolicited STUN message from a remote).
func (p *muxSTUNProber) intercept(data []byte, _ net.Addr) bool {
	// STUN packets: top two bits of first byte are 00, magic cookie at offset 4.
	if len(data) < 20 {
		return false
	}
	if data[0]&0xC0 != 0x00 {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return false
	}
	// Valid STUN packet — always consume so the DHT decoder never sees it.
	// Extract transaction ID (bytes 8–20) and route to any pending probe.
	var txID [12]byte
	copy(txID[:], data[8:20])

	p.mu.Lock()
	ch, ok := p.pending[txID]
	if ok {
		delete(p.pending, txID)
	}
	p.mu.Unlock()

	if !ok {
		// No matching probe; packet is silently discarded.
		return true
	}

	ip, port, err := parseSTUNResponse(data, txID[:])
	if err != nil {
		ch <- stunResult{}
	} else {
		ch <- stunResult{ip: ip, port: port}
	}
	return true
}

// Probe sends a STUN Binding Request to serverAddr on the shared socket and
// waits for the response.  network must be "udp4" or "udp6".
func (p *muxSTUNProber) Probe(ctx context.Context, network, serverAddr string) (net.IP, uint16, error) {
	raddr, err := net.ResolveUDPAddr(network, serverAddr)
	if err != nil {
		return nil, 0, err
	}

	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, 0, err
	}

	// Build STUN Binding Request.
	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01
	binary.BigEndian.PutUint32(req[4:], stunMagicCookie)
	copy(req[8:], txID[:])

	ch := make(chan stunResult, 1)
	p.mu.Lock()
	p.pending[txID] = ch
	p.mu.Unlock()

	if err := p.mux.SendPacket(req, raddr); err != nil {
		p.mu.Lock()
		delete(p.pending, txID)
		p.mu.Unlock()
		return nil, 0, err
	}

	select {
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, txID)
		p.mu.Unlock()
		return nil, 0, ctx.Err()
	case r := <-ch:
		if r.ip == nil {
			return nil, 0, errors.New("stun: invalid response")
		}
		return r.ip, r.port, nil
	}
}

// probeSTUNViaMux queries all STUN servers in parallel on the shared socket
// and returns the first successful (ip, port) pair.  Falls back to probeSTUN
// (ephemeral socket) when prober is nil.
func probeSTUNViaMux(ctx context.Context, prober *muxSTUNProber, network string) (net.IP, uint16) {
	if prober == nil {
		return probeSTUNNetwork(ctx, network)
	}
	type result struct {
		ip   net.IP
		port uint16
	}
	ch := make(chan result, len(stunServers))
	for _, srv := range stunServers {
		srv := srv
		go func() {
			ip, port, err := prober.Probe(ctx, network, srv)
			if err != nil {
				ch <- result{}
				return
			}
			ch <- result{ip, port}
		}()
	}
	for range stunServers {
		if r := <-ch; r.ip != nil {
			return r.ip, r.port
		}
	}
	return nil, 0
}

// httpIPServices are queried as fallback when STUN is unavailable.
var httpIPServices = []string{
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
}

const stunMagicCookie = uint32(0x2112A442)

// probeSTUN queries all STUN servers in parallel over IPv4 and returns the
// first successful external (ip, port) pair. Returns nil ip if all fail.
func probeSTUN(ctx context.Context) (net.IP, uint16) {
	return probeSTUNNetwork(ctx, "udp4")
}

// probeSTUNv6 queries all STUN servers in parallel over IPv6 and returns the
// first successful external (ip, port) pair. Returns nil ip if IPv6 is
// unavailable or all servers fail. Safe to call on IPv4-only hosts.
func probeSTUNv6(ctx context.Context) (net.IP, uint16) {
	return probeSTUNNetwork(ctx, "udp6")
}

func probeSTUNNetwork(ctx context.Context, network string) (net.IP, uint16) {
	type result struct {
		ip   net.IP
		port uint16
	}
	ch := make(chan result, len(stunServers))
	for _, srv := range stunServers {
		srv := srv
		go func() {
			ip, port, err := stunQuery(ctx, network, srv)
			if err != nil {
				ch <- result{}
				return
			}
			ch <- result{ip, port}
		}()
	}
	for range stunServers {
		if r := <-ch; r.ip != nil {
			return r.ip, r.port
		}
	}
	return nil, 0
}

// stunQuery sends a single RFC 5389 Binding Request to serverAddr using the
// given network ("udp4" or "udp6") and parses the XOR-MAPPED-ADDRESS (or
// MAPPED-ADDRESS) attribute from the response. Both address families are
// supported; pass "udp6" for IPv6 STUN probes.
func stunQuery(ctx context.Context, network, serverAddr string) (net.IP, uint16, error) {
	raddr, err := net.ResolveUDPAddr(network, serverAddr)
	if err != nil {
		return nil, 0, err
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(3 * time.Second)
	}
	conn.SetDeadline(dl)

	// Build Binding Request (20-byte header, no attributes).
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, 0, err
	}
	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01 // Message Type: Binding Request
	// req[2:4] = 0 (message length = 0, no attributes)
	binary.BigEndian.PutUint32(req[4:], stunMagicCookie)
	copy(req[8:], txID[:])

	if _, err := conn.WriteToUDP(req, raddr); err != nil {
		return nil, 0, err
	}

	buf := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, 0, err
	}
	return parseSTUNResponse(buf[:n], txID[:])
}

// parseSTUNResponse extracts the mapped address from a STUN Binding Response.
// Supports XOR-MAPPED-ADDRESS (0x0020, preferred) and MAPPED-ADDRESS (0x0001).
func parseSTUNResponse(buf, txID []byte) (net.IP, uint16, error) {
	if len(buf) < 20 {
		return nil, 0, errors.New("stun: response too short")
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
		return nil, 0, errors.New("stun: bad magic cookie")
	}
	if !bytes.Equal(buf[8:20], txID) {
		return nil, 0, errors.New("stun: transaction ID mismatch")
	}
	msgLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if 20+msgLen > len(buf) {
		return nil, 0, errors.New("stun: truncated")
	}

	attrs := buf[20 : 20+msgLen]
	var fallbackIP net.IP
	var fallbackPort uint16

	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+attrLen > len(attrs) {
			break
		}
		val := attrs[4 : 4+attrLen]

		switch attrType {
		case 0x0020: // XOR-MAPPED-ADDRESS (preferred, RFC 5389 §15.2)
			ip, port, ok := decodeXORMappedAddr(val, txID)
			if ok {
				return ip, port, nil
			}
		case 0x0001: // MAPPED-ADDRESS (fallback, RFC 5389 §15.1)
			ip, port, ok := decodeMappedAddr(val)
			if ok {
				fallbackIP, fallbackPort = ip, port
			}
		}
		// Advance past attribute, 4-byte aligned.
		padded := (attrLen + 3) &^ 3
		attrs = attrs[4+padded:]
	}
	if fallbackIP != nil {
		return fallbackIP, fallbackPort, nil
	}
	return nil, 0, errors.New("stun: no mapped address in response")
}

// decodeXORMappedAddr parses the value bytes of a STUN XOR-MAPPED-ADDRESS
// attribute (RFC 5389 §15.2) for both IPv4 (family 0x01) and IPv6 (family 0x02).
// txID is the 12-byte transaction ID from the STUN message header.
func decodeXORMappedAddr(val, txID []byte) (ip net.IP, port uint16, ok bool) {
	if len(val) < 4 {
		return
	}
	port = binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunMagicCookie>>16)
	switch val[1] {
	case 0x01: // IPv4
		if len(val) < 8 {
			return
		}
		rawIP := binary.BigEndian.Uint32(val[4:8]) ^ stunMagicCookie
		ip = make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, rawIP)
		ok = true
	case 0x02: // IPv6 — XOR with stunMagicCookie || txID (RFC 5389 §15.2)
		if len(val) < 20 || len(txID) < 12 {
			return
		}
		ip = make(net.IP, 16)
		xorKey := [16]byte{}
		binary.BigEndian.PutUint32(xorKey[:4], stunMagicCookie)
		copy(xorKey[4:], txID)
		for i := range ip {
			ip[i] = val[4+i] ^ xorKey[i]
		}
		ok = true
	}
	return
}

// decodeMappedAddr parses the value bytes of a STUN MAPPED-ADDRESS attribute
// (RFC 5389 §15.1) for both IPv4 and IPv6. No XOR.
func decodeMappedAddr(val []byte) (ip net.IP, port uint16, ok bool) {
	if len(val) < 4 {
		return
	}
	port = binary.BigEndian.Uint16(val[2:4])
	switch val[1] {
	case 0x01: // IPv4
		if len(val) < 8 {
			return
		}
		ip = make(net.IP, 4)
		copy(ip, val[4:8])
		ok = true
	case 0x02: // IPv6
		if len(val) < 20 {
			return
		}
		ip = make(net.IP, 16)
		copy(ip, val[4:20])
		ok = true
	}
	return
}

// httpPublicIP queries HTTP IP services in parallel and returns the first
// valid public IP. Returns nil if all fail or ctx expires.
func httpPublicIP(ctx context.Context) net.IP {
	type result struct{ ip net.IP }
	ch := make(chan result, len(httpIPServices))
	hc := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range httpIPServices {
		svc := svc
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc, nil)
			if err != nil {
				ch <- result{}
				return
			}
			resp, err := hc.Do(req)
			if err != nil {
				ch <- result{}
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			if err != nil {
				ch <- result{}
				return
			}
			ip := net.ParseIP(strings.TrimSpace(string(b)))
			ch <- result{ip}
		}()
	}
	for range httpIPServices {
		if r := <-ch; r.ip != nil {
			return r.ip
		}
	}
	return nil
}
