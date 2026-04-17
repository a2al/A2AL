// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"github.com/fxamacker/cbor/v2"
)

// SubprotocolICE is negotiated on the WebSocket used for ICE trickle signaling.
const SubprotocolICE = "a2al.ice.v1"

// Frame is a CBOR envelope on the signaling WebSocket.
// T is "cred" | "cand" | "eoc" | "reg" | "incoming" | "noagent".
type Frame struct {
	T string `cbor:"t"`
	U string `cbor:"u,omitempty"` // ufrag (cred)
	P string `cbor:"p,omitempty"` // pwd (cred)
	C string `cbor:"c,omitempty"` // ice candidate Marshal string
	AID    string `cbor:"a,omitempty"` // reg: callee AID; reserved for future use
	Sig    string `cbor:"s,omitempty"` // reg: reserved (AID squatting prevention)
	Room   string `cbor:"r,omitempty"` // incoming: room id
	Caller string `cbor:"f,omitempty"` // incoming: caller AID string
	Target string `cbor:"g,omitempty"` // incoming: callee AID (hub lookup key)
}

// EncodeFrame CBOR-encodes a frame.
func EncodeFrame(f Frame) ([]byte, error) {
	return cbor.Marshal(f)
}

// DecodeFrame decodes a CBOR frame.
func DecodeFrame(b []byte) (Frame, error) {
	var f Frame
	err := cbor.Unmarshal(b, &f)
	return f, err
}
