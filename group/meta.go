// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

const schemaVersion uint8 = 1

// Meta holds the Group's identity and creation parameters.
// Persisted as meta.cbor in the store root directory.
type Meta struct {
	SchemaVersion uint8        `cbor:"1,keyasint"`
	GroupID       [32]byte     `cbor:"2,keyasint"`
	CreatorAID    a2al.Address `cbor:"3,keyasint"`
	Title         string       `cbor:"4,keyasint,omitempty"`
	CreatedAt     int64        `cbor:"5,keyasint"` // Unix seconds
}

// ID returns the Group's persistent identifier.
func (m Meta) ID() [32]byte { return m.GroupID }

// newGroupID derives a Group ID from the creator AID and a cryptographic random nonce.
func newGroupID(creator a2al.Address) ([32]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [32]byte{}, fmt.Errorf("group: random nonce: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("a2al-group-v1:"))
	h.Write(creator[:])
	h.Write(nonce[:])
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id, nil
}

// DMGroupID returns the deterministic Group ID for a one-to-one direct message
// between two AIDs. Both parties can independently compute the same ID without
// any prior communication.
func DMGroupID(a, b a2al.Address) [32]byte {
	// Ensure canonical byte-order so the result is the same regardless of argument order.
	var lo, hi a2al.Address
	if string(a[:]) < string(b[:]) {
		lo, hi = a, b
	} else {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write([]byte("a2al-dm-v1:"))
	h.Write(lo[:])
	h.Write(hi[:])
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// GroupURL returns the canonical a2al:// link for a Group.
// The link embeds the creator AID to provide a routing hint for new members.
func GroupURL(creatorAID a2al.Address, groupID [32]byte) string {
	return fmt.Sprintf("a2al://%s/groups/%s", creatorAID.String(), hex.EncodeToString(groupID[:]))
}

// ParseGroupURL parses a canonical a2al:// Group link produced by GroupURL.
// Returns creatorAID and groupID on success.
// Format: a2al://{creatorAID}/groups/{groupID_hex}
func ParseGroupURL(link string) (creatorAID a2al.Address, groupID [32]byte, err error) {
	const prefix = "a2al://"
	if !strings.HasPrefix(link, prefix) {
		return a2al.Address{}, [32]byte{}, fmt.Errorf("group: link must start with %q", prefix)
	}
	rest := link[len(prefix):]
	parts := strings.SplitN(rest, "/groups/", 2)
	if len(parts) != 2 {
		return a2al.Address{}, [32]byte{}, errors.New("group: invalid link format (expected a2al://{aid}/groups/{id})")
	}
	aid, err := a2al.ParseAddress(parts[0])
	if err != nil {
		return a2al.Address{}, [32]byte{}, fmt.Errorf("group: bad creator AID in link: %w", err)
	}
	b, err := hex.DecodeString(parts[1])
	if err != nil || len(b) != 32 {
		return a2al.Address{}, [32]byte{}, fmt.Errorf("group: bad group ID in link: expected 64 hex chars")
	}
	var id [32]byte
	copy(id[:], b)
	return aid, id, nil
}

// writeMeta persists m to {dir}/meta.cbor atomically.
func writeMeta(dir string, m Meta) error {
	data, err := detEnc.Marshal(m)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "meta.cbor")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readMeta loads and decodes {dir}/meta.cbor.
func readMeta(dir string) (Meta, error) {
	data, err := os.ReadFile(filepath.Join(dir, "meta.cbor"))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := cbor.Unmarshal(data, &m); err != nil {
		return Meta{}, err
	}
	if m.SchemaVersion != schemaVersion {
		return Meta{}, fmt.Errorf("group: unsupported schema version %d (expected %d)", m.SchemaVersion, schemaVersion)
	}
	return m, nil
}

// isGroupDir reports whether dir contains a valid Group store (has meta.cbor).
func isGroupDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "meta.cbor"))
	return err == nil
}

// ensureDir creates dir and all parents if they do not exist.
func ensureDir(path string) error {
	return os.MkdirAll(path, 0o700)
}

// ErrNoStore is returned when Open is called on a path that holds no group
// store. Callers that know the AID and group id should translate it into an
// actionable message naming what to call next, rather than surfacing it raw.
var ErrNoStore = errors.New("group: no local replica")

// ReadMeta reads only the metadata from a group store directory without
// loading the entry index. Use for lightweight enumeration.
func ReadMeta(dir string) (Meta, error) {
	return readMeta(dir)
}

// nowUnix returns the current Unix timestamp in seconds.
// Replaced in tests.
var nowUnix = func() int64 { return time.Now().Unix() }
