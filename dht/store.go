// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

const (
	maxSovereignPerKey  = 8
	maxTopicPerKey      = 100
	maxMailboxPerKey    = 50
	maxMailboxPerPubkey = 4
)

// RecordAuthFunc decides whether a record may be stored at the given DHT key
// after signature and expiry checks (Phase 4: includes key binding for sovereign).
type RecordAuthFunc func(key a2al.NodeID, rec protocol.SignedRecord, now time.Time) error

// ErrStaleRecord means an equal or older record already exists for the same slot.
var ErrStaleRecord = errors.New("dht: stale record")

// Store is an in-memory record map keyed by DHT NodeID (Phase 4 multi-category).
type Store struct {
	mu   sync.Mutex
	m    map[string][]protocol.SignedRecord
	auth RecordAuthFunc // nil → no authority check
}

// NewStore creates an empty Store. auth is optional (see Config.RecordAuth).
func NewStore(auth RecordAuthFunc) *Store {
	return &Store{m: make(map[string][]protocol.SignedRecord), auth: auth}
}

func recordKeyForSigned(rec protocol.SignedRecord) a2al.NodeID {
	var addr a2al.Address
	copy(addr[:], rec.Address)
	return a2al.NodeIDFromAddress(addr)
}

func storageCategory(rec protocol.SignedRecord) uint8 {
	c := protocol.RecordCategory(rec.RecType)
	if c == protocol.CategoryUnknown {
		return protocol.CategorySovereign
	}
	return c
}

// Put stores rec at key. Zero key derives NodeID(rec.Address).
func (s *Store) Put(key a2al.NodeID, rec protocol.SignedRecord, now time.Time) error {
	if err := protocol.VerifySignedRecord(rec, now); err != nil {
		return err
	}
	if key == (a2al.NodeID{}) {
		key = recordKeyForSigned(rec)
	}
	cat := storageCategory(rec)
	if cat == protocol.CategorySovereign {
		if key != recordKeyForSigned(rec) {
			return errors.New("dht: sovereign key mismatch")
		}
	}
	if s.auth != nil {
		if err := s.auth(key, rec, now); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	k := nodeIDKey(key)
	list := s.filterExpiredLocked(s.m[k], now)
	newList, err := mergeAndEvict(list, rec, cat, now)
	if err != nil {
		return err
	}
	s.m[k] = newList
	return nil
}

func mergeAndEvict(list []protocol.SignedRecord, rec protocol.SignedRecord, cat uint8, now time.Time) ([]protocol.SignedRecord, error) {
	switch cat {
	case protocol.CategorySovereign:
		return mergeSovereign(list, rec, now)
	case protocol.CategoryTopic:
		return mergeTopic(list, rec, now)
	case protocol.CategoryMailbox:
		return mergeMailbox(list, rec, now)
	default:
		return mergeSovereign(list, rec, now)
	}
}

func mergeSovereign(list []protocol.SignedRecord, rec protocol.SignedRecord, now time.Time) ([]protocol.SignedRecord, error) {
	for _, r := range list {
		if storageCategory(r) != protocol.CategorySovereign {
			continue
		}
		if string(r.Address) == string(rec.Address) && r.RecType == rec.RecType {
			if protocol.RecordIsNewer(r, rec) {
				return list, ErrStaleRecord
			}
			if !protocol.RecordIsNewer(rec, r) {
				return list, ErrStaleRecord
			}
		}
	}
	out := slices.Clone(list)
	out = slices.DeleteFunc(out, func(r protocol.SignedRecord) bool {
		if storageCategory(r) != protocol.CategorySovereign {
			return false
		}
		return string(r.Address) == string(rec.Address) && r.RecType == rec.RecType
	})
	out = append(out, rec)
	return evictSovereign(out, now), nil
}

func evictSovereign(list []protocol.SignedRecord, now time.Time) []protocol.SignedRecord {
	var sov []protocol.SignedRecord
	var rest []protocol.SignedRecord
	for _, r := range list {
		if storageCategory(r) == protocol.CategorySovereign {
			sov = append(sov, r)
		} else {
			rest = append(rest, r)
		}
	}
	for len(sov) > maxSovereignPerKey {
		// Drop oldest non-endpoint first; never evict 0x01 if others exist.
		idx := -1
		for i, r := range sov {
			if r.RecType != protocol.RecTypeEndpoint {
				idx = i
				break
			}
		}
		if idx < 0 {
			// only endpoints left — drop oldest endpoint by timestamp
			idx = oldestSovereignIndex(sov)
		}
		sov = slices.Delete(sov, idx, idx+1)
	}
	return append(rest, sov...)
}

func oldestSovereignIndex(sov []protocol.SignedRecord) int {
	best := 0
	for i := 1; i < len(sov); i++ {
		if sov[i].Timestamp < sov[best].Timestamp {
			best = i
		}
	}
	return best
}

func mergeTopic(list []protocol.SignedRecord, rec protocol.SignedRecord, now time.Time) ([]protocol.SignedRecord, error) {
	for _, r := range list {
		if storageCategory(r) != protocol.CategoryTopic {
			continue
		}
		if string(r.Pubkey) == string(rec.Pubkey) {
			if protocol.RecordIsNewer(r, rec) {
				return list, ErrStaleRecord
			}
			if !protocol.RecordIsNewer(rec, r) {
				return list, ErrStaleRecord
			}
		}
	}
	out := slices.Clone(list)
	out = slices.DeleteFunc(out, func(r protocol.SignedRecord) bool {
		if storageCategory(r) != protocol.CategoryTopic {
			return false
		}
		return string(r.Pubkey) == string(rec.Pubkey)
	})
	out = append(out, rec)
	return evictTopic(out, now), nil
}

func evictTopic(list []protocol.SignedRecord, now time.Time) []protocol.SignedRecord {
	var topics []protocol.SignedRecord
	var rest []protocol.SignedRecord
	for _, r := range list {
		if storageCategory(r) == protocol.CategoryTopic {
			topics = append(topics, r)
		} else {
			rest = append(rest, r)
		}
	}
	for len(topics) > maxTopicPerKey {
		idx := oldestByTimestampIndex(topics)
		topics = slices.Delete(topics, idx, idx+1)
	}
	return append(rest, topics...)
}

func mergeMailbox(list []protocol.SignedRecord, rec protocol.SignedRecord, now time.Time) ([]protocol.SignedRecord, error) {
	for _, r := range list {
		if storageCategory(r) != protocol.CategoryMailbox {
			continue
		}
		if string(r.Pubkey) == string(rec.Pubkey) && string(r.Payload) == string(rec.Payload) && r.RecType == rec.RecType {
			if protocol.RecordIsNewer(r, rec) {
				return list, ErrStaleRecord
			}
			if !protocol.RecordIsNewer(rec, r) {
				return list, ErrStaleRecord
			}
		}
	}
	out := slices.Clone(list)
	out = slices.DeleteFunc(out, func(r protocol.SignedRecord) bool {
		if storageCategory(r) != protocol.CategoryMailbox {
			return false
		}
		return string(r.Pubkey) == string(rec.Pubkey) && string(r.Payload) == string(rec.Payload) && r.RecType == rec.RecType
	})
	out = append(out, rec)
	return evictMailbox(out, now), nil
}

func evictMailbox(list []protocol.SignedRecord, now time.Time) []protocol.SignedRecord {
	var boxes []protocol.SignedRecord
	var rest []protocol.SignedRecord
	for _, r := range list {
		if storageCategory(r) == protocol.CategoryMailbox {
			boxes = append(boxes, r)
		} else {
			rest = append(rest, r)
		}
	}
	// Per-pubkey cap
	pubCount := make(map[string]int)
	for _, r := range boxes {
		pubCount[string(r.Pubkey)]++
	}
	for {
		over := ""
		for pk, n := range pubCount {
			if n > maxMailboxPerPubkey {
				over = pk
				break
			}
		}
		if over == "" {
			break
		}
		idx := oldestMailboxIndexForPubkey(boxes, over)
		if idx < 0 {
			break
		}
		boxes = slices.Delete(boxes, idx, idx+1)
		pubCount[over]--
	}
	for len(boxes) > maxMailboxPerKey {
		idx := oldestByTimestampIndex(boxes)
		boxes = slices.Delete(boxes, idx, idx+1)
	}
	return append(rest, boxes...)
}

func oldestMailboxIndexForPubkey(boxes []protocol.SignedRecord, pub string) int {
	best := -1
	for i, r := range boxes {
		if string(r.Pubkey) != pub {
			continue
		}
		if best < 0 || r.Timestamp < boxes[best].Timestamp {
			best = i
		}
	}
	return best
}

func oldestByTimestampIndex(rs []protocol.SignedRecord) int {
	best := 0
	for i := 1; i < len(rs); i++ {
		if rs[i].Timestamp < rs[best].Timestamp {
			best = i
		}
	}
	return best
}

// GetAll returns verified non-expired records at key, optionally filtered by RecType (0 = all).
func (s *Store) GetAll(key a2al.NodeID, recType uint8, now time.Time) []protocol.SignedRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.filterExpiredLocked(s.m[nodeIDKey(key)], now)
	var out []protocol.SignedRecord
	for _, r := range list {
		if err := protocol.VerifySignedRecord(r, now); err != nil {
			continue
		}
		if recType != 0 && r.RecType != recType {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Get returns the newest valid endpoint record (RecTypeEndpoint) at key, or nil.
func (s *Store) Get(key a2al.NodeID, now time.Time) *protocol.SignedRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.filterExpiredLocked(s.m[nodeIDKey(key)], now)
	var best *protocol.SignedRecord
	for i := range list {
		r := list[i]
		if r.RecType != protocol.RecTypeEndpoint {
			continue
		}
		if err := protocol.VerifySignedRecord(r, now); err != nil {
			continue
		}
		if best == nil || protocol.RecordIsNewer(r, *best) {
			cp := r
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
