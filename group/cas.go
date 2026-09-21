// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/a2al/a2al"
)

// CASPath is the well-known HTTP path served on an a2cs stream.
func CASPath(id [32]byte) string {
	return "/cas/" + hex.EncodeToString(id[:])
}

// CASURL is the shareable download locator. It never embeds a filesystem path.
func CASURL(holder a2al.Address, id [32]byte) string {
	return fmt.Sprintf("a2al://%s/cas/%s", holder.String(), hex.EncodeToString(id[:]))
}

// ParseCASPath extracts an object id from "/cas/{64hex}" (query string ignored).
func ParseCASPath(p string) (id [32]byte, ok bool) {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSuffix(p, "/")
	const prefix = "/cas/"
	if !strings.HasPrefix(p, prefix) {
		return [32]byte{}, false
	}
	h := p[len(prefix):]
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false
	}
	copy(id[:], b)
	return id, true
}
