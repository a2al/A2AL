// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// Store is an in-memory record map keyed by publisher NodeID (spec Step 7).
type Store struct {
	mu   sync.Mutex
	m    map[string][]protocol.SignedRecord
	auth func(protocol.SignedRecord, time.Time) error // nil → no authority check
}

// NewStore creates an empty Store. auth is an optional authority policy (see Config.RecordAuth).
func NewStore(auth func(protocol.SignedRecord, time.Time) error) *Store {
	return &Store{m: make(map[string][]protocol.SignedRecord), auth: auth}
}

func recordKeyForSigned(rec protocol.SignedRecord) a2al.NodeID {
	var addr a2al.Address
	copy(addr[:], rec.Address)
	return a2al.NodeIDFromAddress(addr)
}

// Put verifies and stores a signed record (replaces same-address entry if newer).
// It checks cryptographic integrity via VerifySignedRecord, then authority via s.auth (if set).
func (s *Store) Put(rec protocol.SignedRecord, now time.Time) error {
	if err := protocol.VerifySignedRecord(rec, now); err != nil {
		return err
	}
	if s.auth != nil {
		if err := s.auth(rec, now); err != nil {
			return err
		}
	}
	key := nodeIDKey(recordKeyForSigned(rec))
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.filterExpiredLocked(s.m[key], now)
	found := false
	for i := range list {
		if string(list[i].Address) == string(rec.Address) {
			if protocol.RecordIsNewer(rec, list[i]) {
				list[i] = rec
			}
			found = true
			break
		}
	}
	if !found {
		list = append(list, rec)
	}
	s.m[key] = list
	return nil
}

// Get returns the freshest valid (non-expired) record for the given key NodeID.
func (s *Store) Get(key a2al.NodeID, now time.Time) *protocol.SignedRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.filterExpiredLocked(s.m[nodeIDKey(key)], now)
	var best *protocol.SignedRecord
	for i := range list {
		if err := protocol.VerifySignedRecord(list[i], now); err != nil {
			continue
		}
		if best == nil || protocol.RecordIsNewer(list[i], *best) {
			cp := list[i]
			best = &cp
		}
	}
	return best
}

func (s *Store) filterExpiredLocked(list []protocol.SignedRecord, now time.Time) []protocol.SignedRecord {
	if len(list) == 0 {
		return list
	}
	u := list[:0]
	for _, r := range list {
		if protocol.VerifySignedRecord(r, now) == nil {
			u = append(u, r)
		}
	}
	return u
}

// Len is the number of distinct key buckets with at least one record.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// StoreRecordDebug is a JSON-friendly store row (spec §3.6).
type StoreRecordDebug struct {
	KeyNodeIDHex string `json:"key_node_id_hex"`
	AddressHex   string `json:"address_hex"`
	RecType      uint8  `json:"rec_type"`
	Seq          uint64 `json:"seq"`
	Timestamp    uint64 `json:"timestamp"`
	TTL          uint32 `json:"ttl_seconds"`
	PayloadLen   int    `json:"payload_cbor_len"`
}

// DebugRecords lists non-expired verified records (spec §3.6).
func (s *Store) DebugRecords(now time.Time) []StoreRecordDebug {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StoreRecordDebug
	for k, list := range s.m {
		list = s.filterExpiredLocked(list, now)
		for _, r := range list {
			if protocol.VerifySignedRecord(r, now) != nil {
				continue
			}
			out = append(out, StoreRecordDebug{
				KeyNodeIDHex: hex.EncodeToString([]byte(k)),
				AddressHex:   hex.EncodeToString(r.Address),
				RecType:      r.RecType,
				Seq:          r.Seq,
				Timestamp:    r.Timestamp,
				TTL:          r.TTL,
				PayloadLen:   len(r.Payload),
			})
		}
	}
	return out
}
