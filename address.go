package a2al

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	// VersionEd25519 is the version byte for Ed25519-derived addresses (spec §6.1).
	VersionEd25519 byte = 0xA0
	addressHexLen          = 42 // 21 bytes × 2
)

// Address is a 21-byte logical address: version byte + 20-byte hash (spec §6.1).
type Address [21]byte

// NodeID is a 256-bit DHT routing key (spec §6.1).
type NodeID [32]byte

// NodeIDFromAddress returns SHA-256(version_byte || hash_20bytes).
func NodeIDFromAddress(addr Address) NodeID {
	var b [1 + 20]byte
	b[0] = addr[0]
	copy(b[1:], addr[1:])
	return sha256.Sum256(b[:])
}

// Distance is the XOR metric d(A,B) = NodeID_A ⊕ NodeID_B (spec §3.3).
func Distance(a, b NodeID) NodeID {
	var d NodeID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// CommonPrefixLen returns the number of leading bits where a and b agree (MSB first).
// If a == b, returns 256.
func CommonPrefixLen(a, b NodeID) int {
	x := Distance(a, b)
	for i := 0; i < len(x); i++ {
		if x[i] != 0 {
			return i*8 + bits.LeadingZeros8(x[i])
		}
	}
	return 256
}

// String returns the checksummed hex form (spec §6.2, SHA-256 variant of EIP-55).
func (a Address) String() string {
	lower := fmt.Sprintf("%x", a[:])
	return checksumAddressHex(lower)
}

// ParseAddress parses a 42-character hex address. All-lowercase input is accepted
// without checksum verification; mixed-case must match the SHA-256 checksum encoding.
func ParseAddress(s string) (Address, error) {
	if len(s) != addressHexLen {
		return Address{}, fmt.Errorf("%w: want %d hex chars", ErrInvalidAddress, addressHexLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return Address{}, ErrInvalidAddress
		}
	}
	lower := toLowerHex(s)
	raw, err := hex.DecodeString(lower)
	if err != nil || len(raw) != len(Address{}) {
		return Address{}, ErrInvalidAddress
	}
	if raw[0] < 0xA0 || raw[0] > 0xAF {
		return Address{}, ErrInvalidAddress
	}
	expected := checksumAddressHex(lower)
	if s != expected && s != lower {
		return Address{}, ErrInvalidAddress
	}
	var out Address
	copy(out[:], raw)
	return out, nil
}

func toLowerHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func checksumAddressHex(lower string) string {
	h := sha256.Sum256([]byte(lower))
	out := make([]byte, 0, addressHexLen)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
			continue
		}
		v := h[i/2]
		var nib byte
		if i%2 == 0 {
			nib = v >> 4
		} else {
			nib = v & 0x0f
		}
		if nib >= 8 {
			out = append(out, c-('a'-'A'))
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}
