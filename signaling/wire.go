// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package signaling

import (
	"github.com/fxamacker/cbor/v2"
)

// SubprotocolICE is negotiated on the WebSocket used for ICE trickle signaling.
const SubprotocolICE = "a2al.ice.v1"

// Frame is a CBOR envelope on the signaling WebSocket.
// T is "cred" | "cand" | "eoc".
type Frame struct {
	T string `cbor:"t"`
	U string `cbor:"u,omitempty"` // ufrag (cred)
	P string `cbor:"p,omitempty"` // pwd (cred)
	C string `cbor:"c,omitempty"` // ice candidate Marshal string
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
