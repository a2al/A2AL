// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildSTUNResponse constructs a minimal STUN Binding Success Response
// containing a single XOR-MAPPED-ADDRESS attribute.
func buildSTUNResponse(txID []byte, family byte, ip net.IP, port uint16) []byte {
	// XOR-MAPPED-ADDRESS value bytes:
	//   [0]   = 0x00 (unused)
	//   [1]   = family (0x01=IPv4, 0x02=IPv6)
	//   [2:4] = port ^ (magic >> 16)
	//   [4:]  = XOR'd address
	xorPort := port ^ uint16(stunMagicCookie>>16)
	var addrBytes []byte
	switch family {
	case 0x01: // IPv4
		raw := binary.BigEndian.Uint32(ip.To4()) ^ stunMagicCookie
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, raw)
		addrBytes = b
	case 0x02: // IPv6
		xorKey := [16]byte{}
		binary.BigEndian.PutUint32(xorKey[:4], stunMagicCookie)
		copy(xorKey[4:], txID)
		xored := make([]byte, 16)
		for i := range xored {
			xored[i] = ip[i] ^ xorKey[i]
		}
		addrBytes = xored
	}

	val := append([]byte{0x00, family}, 0, 0) // unused + family + 2-byte port placeholder
	binary.BigEndian.PutUint16(val[2:], xorPort)
	val = append(val, addrBytes...)

	attrLen := len(val)
	// Pad to 4-byte alignment.
	padded := (attrLen + 3) &^ 3
	attr := make([]byte, 4+padded)
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], uint16(attrLen))
	copy(attr[4:], val)

	// STUN header: type(2) + msgLen(2) + magic(4) + txID(12) = 20 bytes
	msgLen := len(attr)
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0101) // Binding Success Response
	binary.BigEndian.PutUint16(hdr[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(hdr[4:8], stunMagicCookie)
	copy(hdr[8:], txID)
	return append(hdr, attr...)
}

func TestParseSTUNResponse_IPv4(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i + 1)
	}
	wantIP := net.IPv4(1, 2, 3, 4).To4()
	wantPort := uint16(54321)

	buf := buildSTUNResponse(txID, 0x01, wantIP, wantPort)
	ip, port, err := parseSTUNResponse(buf, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse IPv4: %v", err)
	}
	if !ip.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", ip, wantIP)
	}
	if port != wantPort {
		t.Errorf("port: got %d, want %d", port, wantPort)
	}
}

func TestParseSTUNResponse_IPv6(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(0xAA + i)
	}
	wantIP := net.ParseIP("2001:db8::1").To16()
	wantPort := uint16(12345)

	buf := buildSTUNResponse(txID, 0x02, wantIP, wantPort)
	ip, port, err := parseSTUNResponse(buf, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse IPv6: %v", err)
	}
	if !ip.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", ip, wantIP)
	}
	if port != wantPort {
		t.Errorf("port: got %d, want %d", port, wantPort)
	}
	if len(ip) != net.IPv6len {
		t.Errorf("expected 16-byte IPv6, got len=%d", len(ip))
	}
}

func TestDecodeXORMappedAddr_edgeCases(t *testing.T) {
	txID := make([]byte, 12)

	// Too-short value for IPv4
	_, _, ok := decodeXORMappedAddr([]byte{0x00, 0x01, 0x00, 0x00, 0x00}, txID) // only 5 bytes, need 8
	if ok {
		t.Error("should fail for short IPv4 val")
	}

	// Too-short value for IPv6
	_, _, ok = decodeXORMappedAddr([]byte{0x00, 0x02, 0x00, 0x00, 0x01, 0x02}, txID) // only 6 bytes, need 20
	if ok {
		t.Error("should fail for short IPv6 val")
	}

	// Unknown family
	_, _, ok = decodeXORMappedAddr([]byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}, txID)
	if ok {
		t.Error("should fail for unknown family")
	}
}

func TestDecodeMappedAddr(t *testing.T) {
	// IPv4 MAPPED-ADDRESS: family=0x01, port=12345, ip=1.2.3.4
	port := uint16(12345)
	ip := net.ParseIP("1.2.3.4").To4()
	val := []byte{
		0x00, 0x01, // family
		byte(port >> 8), byte(port), // port
		ip[0], ip[1], ip[2], ip[3], // ip
	}
	gotIP, gotPort, ok := decodeMappedAddr(val)
	if !ok {
		t.Fatal("decodeMappedAddr IPv4: expected ok")
	}
	if !gotIP.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("IPv4 IP: got %v, want 1.2.3.4", gotIP)
	}
	if gotPort != port {
		t.Errorf("IPv4 port: got %d, want %d", gotPort, port)
	}

	// IPv6 MAPPED-ADDRESS: family=0x02, port=443, ip=2001:db8::1
	port6 := uint16(443)
	ip6 := net.ParseIP("2001:db8::1").To16()
	val6 := append([]byte{0x00, 0x02, byte(port6 >> 8), byte(port6)}, ip6...)
	gotIP6, gotPort6, ok6 := decodeMappedAddr(val6)
	if !ok6 {
		t.Fatal("decodeMappedAddr IPv6: expected ok")
	}
	if !gotIP6.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("IPv6 IP: got %v, want 2001:db8::1", gotIP6)
	}
	if gotPort6 != port6 {
		t.Errorf("IPv6 port: got %d, want %d", gotPort6, port6)
	}

	// Short value → not ok
	_, _, bad := decodeMappedAddr([]byte{0x00, 0x01, 0x00})
	if bad {
		t.Error("expected failure for short value")
	}
}
