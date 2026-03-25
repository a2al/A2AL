// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package protocol

// Message type IDs (spec §7.4).
const (
	MsgPing           uint8 = 0x01
	MsgPong           uint8 = 0x02
	MsgFindNode       uint8 = 0x03
	MsgFindNodeResp   uint8 = 0x04
	MsgFindValue      uint8 = 0x05
	MsgFindValueResp  uint8 = 0x06
	MsgStore          uint8 = 0x07
	MsgStoreResp      uint8 = 0x08
)

// ProtocolVersion is the wire protocol version (spec §7.3).
const ProtocolVersion uint8 = 1

// Header is the CBOR map in field 1 of the outer message (spec §7.3).
type Header struct {
	Version  uint8  `cbor:"1,keyasint"`
	Features uint16 `cbor:"2,keyasint"`
	MsgType  uint8  `cbor:"3,keyasint"`
	TxID     []byte `cbor:"4,keyasint"`
}

// NodeInfo is the DHT routing contact shape (spec §7.6).
type NodeInfo struct {
	Address []byte `cbor:"1,keyasint"` // 21 bytes
	NodeID  []byte `cbor:"2,keyasint"` // 32 bytes
	IP      []byte `cbor:"3,keyasint"` // 4 or 16 bytes
	Port    uint16 `cbor:"4,keyasint"`
}

// SignedRecord is the on-wire record container (spec §7.6). Record signing uses
// prefix "a2al-rec\0" over CBOR of fields 1–6 (implemented in record.go, Step 4).
// Field 9 (Delegation) is optional and carries a CBOR-encoded DelegationProof when
// the signing key (Pubkey) is an operational key publishing on behalf of a master-derived Address.
type SignedRecord struct {
	Address    []byte `cbor:"1,keyasint"`
	RecType    uint8  `cbor:"2,keyasint"`
	Payload    []byte `cbor:"3,keyasint"`
	Seq        uint64 `cbor:"4,keyasint"`
	Timestamp  uint64 `cbor:"5,keyasint"`
	TTL        uint32 `cbor:"6,keyasint"`
	Pubkey     []byte `cbor:"7,keyasint"`
	Signature  []byte `cbor:"8,keyasint"`
	Delegation []byte `cbor:"9,keyasint,omitempty"`
}

// Body types (spec §7.5).

type BodyPing struct {
	Address []byte `cbor:"1,keyasint"` // 21
}

type BodyPong struct {
	Address      []byte `cbor:"1,keyasint"`
	ObservedAddr []byte `cbor:"2,keyasint"` // 6 or 18
}

type BodyFindNode struct {
	Target []byte `cbor:"1,keyasint"` // 32 NodeID
}

type BodyFindNodeResp struct {
	Nodes        []NodeInfo `cbor:"1,keyasint"`
	ObservedAddr []byte     `cbor:"2,keyasint"`
}

type BodyFindValue struct {
	Target  []byte `cbor:"1,keyasint"`
	RecType uint8  `cbor:"2,keyasint,omitempty"` // 0 = all types
}

type BodyFindValueResp struct {
	Nodes        []NodeInfo     `cbor:"1,keyasint"`
	Record       *SignedRecord  `cbor:"2,keyasint,omitempty"`
	ObservedAddr []byte         `cbor:"3,keyasint"`
	Records      []SignedRecord `cbor:"4,keyasint,omitempty"`
}

type BodyStore struct {
	Record SignedRecord `cbor:"1,keyasint"`
	Key    []byte       `cbor:"2,keyasint,omitempty"` // 32-byte DHT key; omit = NodeID(Address)
}

type BodyStoreResp struct {
	Stored bool `cbor:"1,keyasint"`
}
