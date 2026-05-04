// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// RecTypeAgentProfile is the sovereign RecType for AgentProfilePayload (0x02).
const RecTypeAgentProfile uint8 = 0x02

// AgentProfilePayloadWarnSize is a soft advisory threshold (bytes).
// Payloads approaching this size may compete with routing nodes for UDP packet space.
const AgentProfilePayloadWarnSize = 350

// AgentProfilePayloadMaxSize is the hard pre-publish rejection threshold (bytes).
// The FIND_VALUE response budget is ~1050 B; SignedRecord wrapper adds ~156 B,
// leaving ≈894 B for payload. We cap at 700 B to keep routing nodes comfortable.
const AgentProfilePayloadMaxSize = 700

// AgentProfilePayload is the CBOR body of a RecType=0x02 sovereign record.
// All fields except Version are optional (omitempty).
// Integer map keys minimise wire footprint under the 700 B cap.
type AgentProfilePayload struct {
	Version    uint8          `cbor:"1,keyasint"`
	Name       string         `cbor:"2,keyasint,omitempty"`
	Brief      string         `cbor:"3,keyasint,omitempty"`
	Protocols  []string       `cbor:"4,keyasint,omitempty"`
	Skills     []string       `cbor:"5,keyasint,omitempty"`
	CardHash   []byte         `cbor:"6,keyasint,omitempty"`
	Modalities []string       `cbor:"8,keyasint,omitempty"`
	Meta       map[string]any `cbor:"9,keyasint,omitempty"`
}

// MarshalAgentProfilePayload canonical-encodes p and enforces the size limit.
// Returns ErrPayloadApproachingLimit (non-fatal) wrapped in the error when the
// payload is within the hard limit but above the advisory threshold.
func MarshalAgentProfilePayload(p AgentProfilePayload) ([]byte, error) {
	if p.Version == 0 {
		p.Version = 1
	}
	b, err := recordCanonical.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > AgentProfilePayloadMaxSize {
		return nil, fmt.Errorf("%w: agent profile payload exceeds %d bytes (%d)", ErrInvalidRecord, AgentProfilePayloadMaxSize, len(b))
	}
	if len(b) > AgentProfilePayloadWarnSize {
		// Caller may log a warning; not a hard error.
		return b, fmt.Errorf("%w: %d bytes (advisory limit %d)", ErrPayloadApproachingLimit, len(b), AgentProfilePayloadWarnSize)
	}
	return b, nil
}

// ParseAgentProfilePayload decodes the payload from a RecType=0x02 SignedRecord.
func ParseAgentProfilePayload(sr SignedRecord) (AgentProfilePayload, error) {
	if sr.RecType != RecTypeAgentProfile {
		return AgentProfilePayload{}, fmt.Errorf("%w: expected RecType 0x02, got 0x%02x", ErrInvalidRecord, sr.RecType)
	}
	if len(sr.Payload) > AgentProfilePayloadMaxSize {
		return AgentProfilePayload{}, fmt.Errorf("%w: agent profile payload too large (%d)", ErrInvalidRecord, len(sr.Payload))
	}
	var p AgentProfilePayload
	if err := cbor.Unmarshal(sr.Payload, &p); err != nil {
		return AgentProfilePayload{}, err
	}
	return p, nil
}
