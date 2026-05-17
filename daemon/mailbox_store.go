// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/sha256"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	mailboxStoreFlushInterval = 5 * time.Second
	mailboxStoreTTLCleanup    = 10 * time.Minute
	mailboxStoreMaxPerAID     = 200
)

// MailboxStoreEntry is one persisted mailbox record.
type MailboxStoreEntry struct {
	RecipientAID a2al.Address         `cbor:"1,keyasint"`
	Record       protocol.SignedRecord `cbor:"2,keyasint"` // encrypted; zero-value when sourced from old-style poll
	ReceivedAt   int64                `cbor:"3,keyasint"`
	TTLExpires   int64                `cbor:"4,keyasint"`
	ConsumedAt   int64                `cbor:"5,keyasint,omitempty"` // 0 = unconsumed
}

// MsgIDFromRecord computes a stable deduplication key: SHA-256(SignedRecord.Payload).
// When Payload is empty (legacy entry), it falls back to SHA-256(Address + Seq CBOR).
func MsgIDFromRecord(sr protocol.SignedRecord) [32]byte {
	if len(sr.Payload) > 0 {
		return sha256.Sum256(sr.Payload)
	}
	// Fallback for empty-record entries stored during transitional M2 period.
	h := sha256.New()
	h.Write(sr.Address)
	var seq [8]byte
	seq[0] = byte(sr.Seq >> 56)
	seq[1] = byte(sr.Seq >> 48)
	seq[2] = byte(sr.Seq >> 40)
	seq[3] = byte(sr.Seq >> 32)
	seq[4] = byte(sr.Seq >> 24)
	seq[5] = byte(sr.Seq >> 16)
	seq[6] = byte(sr.Seq >> 8)
	seq[7] = byte(sr.Seq)
	h.Write(seq[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type mailboxStore struct {
	path string
	log  *slog.Logger

	mu      sync.RWMutex
	byMsgID map[[32]byte]*MailboxStoreEntry
	byAID   map[a2al.Address][]*MailboxStoreEntry
	dirty   bool
}

func newMailboxStore(path string, log *slog.Logger) *mailboxStore {
	return &mailboxStore{
		path:    path,
		log:     log,
		byMsgID: make(map[[32]byte]*MailboxStoreEntry),
		byAID:   make(map[a2al.Address][]*MailboxStoreEntry),
	}
}

// Load reads the store from disk into memory. Call once at startup.
func (s *mailboxStore) Load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []MailboxStoreEntry
	if err := cbor.Unmarshal(data, &entries); err != nil {
		s.log.Warn("mailbox store: corrupt file, starting fresh", "err", err)
		return nil
	}
	now := time.Now().Unix()
	for i := range entries {
		e := &entries[i]
		if e.TTLExpires > 0 && e.TTLExpires < now {
			continue
		}
		id := MsgIDFromRecord(e.Record)
		s.byMsgID[id] = e
		s.byAID[e.RecipientAID] = append(s.byAID[e.RecipientAID], e)
	}
	return nil
}

// Put stores a new entry. No-op if msg_id already exists. Returns true if inserted.
func (s *mailboxStore) Put(msgID [32]byte, e MailboxStoreEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byMsgID[msgID]; ok {
		return false
	}
	entry := &MailboxStoreEntry{
		RecipientAID: e.RecipientAID,
		Record:       e.Record,
		ReceivedAt:   e.ReceivedAt,
		TTLExpires:   e.TTLExpires,
		ConsumedAt:   e.ConsumedAt,
	}
	s.byMsgID[msgID] = entry
	s.byAID[e.RecipientAID] = append(s.byAID[e.RecipientAID], entry)
	s.dirty = true
	return true
}

// Has reports whether msgID exists (including consumed records).
func (s *mailboxStore) Has(msgID [32]byte) bool {
	s.mu.RLock()
	_, ok := s.byMsgID[msgID]
	s.mu.RUnlock()
	return ok
}

// GetUnconsumed returns all unconsumed entries for aid, sorted oldest-first.
func (s *mailboxStore) GetUnconsumed(aid a2al.Address) ([]*MailboxStoreEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.byAID[aid]
	out := make([]*MailboxStoreEntry, 0, len(all))
	for _, e := range all {
		if e.ConsumedAt == 0 {
			out = append(out, e)
		}
	}
	return out, nil
}

// MarkConsumed sets ConsumedAt for msgID to now.
func (s *mailboxStore) MarkConsumed(msgID [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byMsgID[msgID]; ok && e.ConsumedAt == 0 {
		e.ConsumedAt = time.Now().Unix()
		s.dirty = true
	}
}

// Flush writes the full store to disk if dirty.
func (s *mailboxStore) Flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	entries := make([]MailboxStoreEntry, 0, len(s.byMsgID))
	for _, e := range s.byMsgID {
		entries = append(entries, *e)
	}
	s.dirty = false
	s.mu.Unlock()

	data, err := cbor.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Cleanup removes TTL-expired entries and enforces the per-AID cap.
// Must be called periodically.
func (s *mailboxStore) Cleanup() {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, e := range s.byMsgID {
		if e.TTLExpires > 0 && e.TTLExpires < now {
			delete(s.byMsgID, id)
			s.dirty = true
		}
	}

	// Rebuild byAID and enforce cap.
	for aid := range s.byAID {
		var live []*MailboxStoreEntry
		for _, e := range s.byAID[aid] {
			if _, ok := s.byMsgID[MsgIDFromRecord(e.Record)]; ok {
				live = append(live, e)
			}
		}
		// Trim to cap: prefer evicting consumed entries, then oldest unconsumed.
		for len(live) > mailboxStoreMaxPerAID {
			removed := false
			for i, e := range live {
				if e.ConsumedAt > 0 {
					delete(s.byMsgID, MsgIDFromRecord(e.Record))
					live = append(live[:i], live[i+1:]...)
					s.dirty = true
					removed = true
					break
				}
			}
			if !removed {
				delete(s.byMsgID, MsgIDFromRecord(live[0].Record))
				live = live[1:]
				s.dirty = true
			}
		}
		if len(live) == 0 {
			delete(s.byAID, aid)
		} else {
			s.byAID[aid] = live
		}
	}
}

// runBackground starts the periodic flush and cleanup goroutines.
// The goroutines stop when ctx is done.
func (s *mailboxStore) runBackground(stopCh <-chan struct{}) {
	flushTicker := time.NewTicker(mailboxStoreFlushInterval)
	cleanupTicker := time.NewTicker(mailboxStoreTTLCleanup)
	defer flushTicker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-flushTicker.C:
			if err := s.Flush(); err != nil {
				s.log.Warn("mailbox store: flush error", "err", err)
			}
		case <-cleanupTicker.C:
			s.Cleanup()
			if err := s.Flush(); err != nil {
				s.log.Warn("mailbox store: flush after cleanup error", "err", err)
			}
		case <-stopCh:
			return
		}
	}
}
