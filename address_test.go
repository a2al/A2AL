package a2al

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNodeIDFromAddress_deterministic(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xab}, 20))
	id1 := NodeIDFromAddress(addr)
	id2 := NodeIDFromAddress(addr)
	if id1 != id2 {
		t.Fatal("NodeID not deterministic")
	}
	var manual [32]byte
	var input [21]byte
	copy(input[:], addr[:])
	manual = sha256.Sum256(input[:])
	if id1 != manual {
		t.Fatalf("NodeID mismatch: got %x want %x", id1[:], manual[:])
	}
}

func TestDistance_symmetric(t *testing.T) {
	var a, b NodeID
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(255 - i)
	}
	dab := Distance(a, b)
	dba := Distance(b, a)
	if dab != dba {
		t.Fatal("XOR distance not symmetric")
	}
	var zero NodeID
	if Distance(zero, zero) != zero {
		t.Fatal("self-distance not zero")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	var a, b NodeID
	if CommonPrefixLen(a, b) != 256 {
		t.Fatal("identical IDs should have CPL 256")
	}
	a[0] = 0x80
	b[0] = 0x00
	if CommonPrefixLen(a, b) != 0 {
		t.Fatalf("want CPL 0, got %d", CommonPrefixLen(a, b))
	}
	a[0] = 0x40
	b[0] = 0x00
	if CommonPrefixLen(a, b) != 1 {
		t.Fatalf("want CPL 1, got %d", CommonPrefixLen(a, b))
	}
}

func TestAddressString_roundTrip(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xcd}, 20))
	s := addr.String()
	if len(s) != addressHexLen {
		t.Fatalf("len %d", len(s))
	}
	back, err := ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	if back != addr {
		t.Fatalf("round trip: got %x want %x", back[:], addr[:])
	}
}

func TestParseAddress_lowercaseAccepted(t *testing.T) {
	lower := strings.ToLower("A0" + strings.Repeat("cd", 20))
	addr, err := ParseAddress(lower)
	if err != nil {
		t.Fatal(err)
	}
	if addr[0] != VersionEd25519 {
		t.Fatal(addr[0])
	}
}

func TestParseAddress_badChecksum(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xef}, 20))
	good := addr.String()
	// flip case on one letter that should be lower
	bad := []byte(good)
	for i, c := range bad {
		if c >= 'A' && c <= 'F' {
			bad[i] = c - 'A' + 'a'
			break
		}
	}
	_, err := ParseAddress(string(bad))
	if err == nil {
		t.Fatal("expected error for bad checksum")
	}
}

func TestParseAddress_invalidVersion(t *testing.T) {
	raw := make([]byte, 21)
	raw[0] = 0x99
	s := hex.EncodeToString(raw)
	_, err := ParseAddress(s)
	if err == nil {
		t.Fatal("expected error")
	}
}
