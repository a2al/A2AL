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
	"time"
)

// STUN servers queried for external IP:port (RFC 5389 Binding Request).
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// httpIPServices are queried as fallback when STUN is unavailable.
var httpIPServices = []string{
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
}

const stunMagicCookie = uint32(0x2112A442)

// probeSTUN tries all STUN servers in parallel and returns the first successful
// external (ip, port) pair. Returns nil ip if all fail.
func probeSTUN(ctx context.Context) (net.IP, uint16) {
	type result struct {
		ip   net.IP
		port uint16
	}
	ch := make(chan result, len(stunServers))
	for _, srv := range stunServers {
		srv := srv
		go func() {
			ip, port, err := stunQuery(ctx, srv)
			if err != nil {
				ch <- result{}
				return
			}
			ch <- result{ip, port}
		}()
	}
	for range stunServers {
		r := <-ch
		if r.ip != nil {
			return r.ip, r.port
		}
	}
	return nil, 0
}

// stunQuery sends a single RFC 5389 Binding Request to serverAddr and parses
// the XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) attribute from the response.
func stunQuery(ctx context.Context, serverAddr string) (net.IP, uint16, error) {
	raddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, 0, err
	}
	conn, err := net.ListenUDP("udp4", nil)
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
		case 0x0020: // XOR-MAPPED-ADDRESS (preferred)
			if len(val) >= 8 && val[1] == 0x01 { // IPv4 family
				port := binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunMagicCookie>>16)
				rawIP := binary.BigEndian.Uint32(val[4:8]) ^ stunMagicCookie
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, rawIP)
				return ip, port, nil
			}
		case 0x0001: // MAPPED-ADDRESS (fallback)
			if len(val) >= 8 && val[1] == 0x01 {
				fallbackPort = binary.BigEndian.Uint16(val[2:4])
				fallbackIP = make(net.IP, 4)
				copy(fallbackIP, val[4:8])
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
