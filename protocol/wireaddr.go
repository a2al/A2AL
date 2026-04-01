// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ParseObservedUDP decodes wire observed_addr (4+2 IPv4 or 16+2 IPv6, big-endian port).
func ParseObservedUDP(b []byte) (host string, port uint16, ok bool) {
	switch len(b) {
	case 6:
		ip := net.IP(b[:4])
		ip4 := ip.To4()
		if ip4 == nil {
			return "", 0, false
		}
		p := binary.BigEndian.Uint16(b[4:6])
		return ip4.String(), p, true
	case 18:
		ip := net.IP(b[:16])
		if ip.To16() == nil {
			return "", 0, false
		}
		p := binary.BigEndian.Uint16(b[16:18])
		return ip.String(), p, true
	default:
		return "", 0, false
	}
}

// FormatObservedUDP encodes IP:port to the same wire form as BodyPong.observed_addr.
func FormatObservedUDP(ip net.IP, port uint16) ([]byte, error) {
	if ip4 := ip.To4(); ip4 != nil {
		out := append([]byte(nil), ip4...)
		return binary.BigEndian.AppendUint16(out, port), nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("protocol: invalid IP")
	}
	out := append([]byte(nil), ip16...)
	return binary.BigEndian.AppendUint16(out, port), nil
}
