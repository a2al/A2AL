// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package chat is the local roster and per-peer linear log for AID-to-AID
// messaging. It has no network of its own.
package chat

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

const (
	StateOutPending = "out_pending"
	StateInPending  = "in_pending"
	StateMutual     = "mutual"
	StateBlocked    = "blocked"

	DirOut = "out"
	DirIn  = "in"

	StatusLocal = "local"
	StatusSent  = "sent"
	StatusIn    = "in"

	KindText = "text"
	KindFile = "file"

	PendingCap    = 32
	IgnoreTTL     = 72 * time.Hour
	DingMerge     = time.Hour
	NoteMaxRunes  = 80
	DefaultLimit  = 50
	PurposeInvite = "chat.invite"
	PowMaxAge     = 24 * time.Hour
)

var (
	ErrSelf        = errors.New("chat: cannot message this identity")
	ErrNotFriends  = errors.New("not_friends: the peer is not on this identity's chat list — call chat_request first")
	ErrAlready     = errors.New("chat: already requested or friends")
	ErrBlocked     = errors.New("chat: this peer is blocked")
	ErrNotPending  = errors.New("chat: no pending invite from that peer")
	ErrPendingFull = errors.New("chat: pending invite list is full")
	ErrHasInbound  = errors.New("chat: inbound invite already pending")
	ErrBadState    = errors.New("chat: invalid roster state")
	ErrSignaling   = errors.New("chat: signaling not delivered")
)

type RosterEntry struct {
	Peer    a2al.Address
	State   string
	Since   int64
	Note    string
	DingAt  int64
	ReadIdx uint64 // exclusive local log index already marked read
}

type Rec struct {
	Seq    uint64
	Dir    string
	TS     int64
	Kind   string
	Body   string
	Ref    [32]byte
	Name   string
	Size   int64
	Status string
	Author a2al.Address
	Grant  string
	Idx    uint64 // 1-based local log index; set on Read, not stored
}

type Store struct {
	dir string
	mu  sync.Mutex
	now func() time.Time

	roster map[a2al.Address]RosterEntry
	logs   map[a2al.Address]*peerLog
}

type peerLog struct {
	recs []Rec
	next uint64
}

type rosterFile struct {
	Entries []rosterWire `cbor:"1,keyasint"`
}

type rosterWire struct {
	Peer    []byte `cbor:"1,keyasint"`
	State   string `cbor:"2,keyasint"`
	Since   int64  `cbor:"3,keyasint"`
	Note    string `cbor:"4,keyasint,omitempty"`
	DingAt  int64  `cbor:"5,keyasint,omitempty"`
	ReadIdx uint64 `cbor:"6,keyasint,omitempty"`
}

type logFile struct {
	Recs []recWire `cbor:"1,keyasint"`
	Next uint64    `cbor:"2,keyasint"`
}

type recWire struct {
	Seq    uint64 `cbor:"1,keyasint"`
	Dir    string `cbor:"2,keyasint"`
	TS     int64  `cbor:"3,keyasint"`
	Kind   string `cbor:"4,keyasint"`
	Body   string `cbor:"5,keyasint,omitempty"`
	Ref    []byte `cbor:"6,keyasint,omitempty"`
	Name   string `cbor:"7,keyasint,omitempty"`
	Size   int64  `cbor:"8,keyasint,omitempty"`
	Status string `cbor:"9,keyasint"`
	Author []byte `cbor:"10,keyasint,omitempty"`
	Grant  string `cbor:"11,keyasint,omitempty"`
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{
		dir:    dir,
		now:    time.Now,
		roster: make(map[a2al.Address]RosterEntry),
		logs:   make(map[a2al.Address]*peerLog),
	}
	if err := s.loadRoster(); err != nil {
		return nil, err
	}
	s.sweepLocked()
	return s, nil
}

func (s *Store) SetNow(fn func() time.Time) {
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
}

func (s *Store) Get(peer a2al.Address) (RosterEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	e, ok := s.roster[peer]
	return e, ok
}

func (s *Store) Contacts() []RosterEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	out := make([]RosterEntry, 0, len(s.roster))
	for _, e := range s.roster {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b RosterEntry) int {
		if a.Since != b.Since {
			if a.Since > b.Since {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.Peer[:], b.Peer[:])
	})
	return out
}

func (s *Store) InPendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	n := 0
	for _, e := range s.roster {
		if e.State == StateInPending {
			n++
		}
	}
	return n
}

func (s *Store) UnreadCount(peer a2al.Address) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unreadLocked(peer)
}

func (s *Store) TotalUnread() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for peer := range s.roster {
		n += s.unreadLocked(peer)
	}
	return n
}

func (s *Store) ReadCursor(peer a2al.Address) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.roster[peer]
	if !ok {
		return 0
	}
	return e.ReadIdx
}

func (s *Store) MarkRead(peer a2al.Address, scannedTo uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.roster[peer]
	if !ok {
		return nil
	}
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return err
	}
	n := uint64(len(pl.recs))
	if scannedTo == 0 || scannedTo > n {
		scannedTo = n
	}
	if scannedTo < e.ReadIdx {
		return nil
	}
	e.ReadIdx = scannedTo
	s.roster[peer] = e
	return s.saveRosterLocked()
}

func (s *Store) unreadLocked(peer a2al.Address) int {
	e, ok := s.roster[peer]
	if !ok || e.State == StateBlocked {
		return 0
	}
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return 0
	}
	start := int(e.ReadIdx)
	if start < 0 {
		start = 0
	}
	if start > len(pl.recs) {
		start = len(pl.recs)
	}
	n := 0
	for i := start; i < len(pl.recs); i++ {
		if pl.recs[i].Dir == DirIn {
			n++
		}
	}
	return n
}

func (s *Store) PutOutPending(peer a2al.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if e, ok := s.roster[peer]; ok {
		switch e.State {
		case StateOutPending:
			return nil
		case StateMutual:
			return ErrAlready
		case StateBlocked:
			return ErrBlocked
		case StateInPending:
			return ErrHasInbound
		default:
			return ErrBadState
		}
	}
	s.roster[peer] = RosterEntry{Peer: peer, State: StateOutPending, Since: s.now().Unix()}
	return s.saveRosterLocked()
}

func (s *Store) PutInPending(peer a2al.Address, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if e, ok := s.roster[peer]; ok {
		switch e.State {
		case StateBlocked:
			return ErrBlocked
		case StateMutual, StateOutPending, StateInPending:
			return ErrAlready
		}
	}
	n := 0
	for _, e := range s.roster {
		if e.State == StateInPending {
			n++
		}
	}
	if n >= PendingCap {
		return ErrPendingFull
	}
	s.roster[peer] = RosterEntry{Peer: peer, State: StateInPending, Since: s.now().Unix(), Note: TruncateRunes(note, NoteMaxRunes)}
	return s.saveRosterLocked()
}

func (s *Store) SetMutual(peer a2al.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	e, ok := s.roster[peer]
	if !ok {
		s.roster[peer] = RosterEntry{Peer: peer, State: StateMutual, Since: s.now().Unix()}
		return s.saveRosterLocked()
	}
	if e.State == StateBlocked {
		return ErrBlocked
	}
	e.State = StateMutual
	e.Note = ""
	s.roster[peer] = e
	return s.saveRosterLocked()
}

func (s *Store) Delete(peer a2al.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roster, peer)
	delete(s.logs, peer)
	_ = os.RemoveAll(s.peerDir(peer))
	return s.saveRosterLocked()
}

func (s *Store) Block(peer a2al.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roster[peer] = RosterEntry{Peer: peer, State: StateBlocked, Since: s.now().Unix()}
	delete(s.logs, peer)
	_ = os.RemoveAll(s.peerDir(peer))
	return s.saveRosterLocked()
}

func (s *Store) TouchDing(peer a2al.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.roster[peer]
	if !ok {
		return nil
	}
	e.DingAt = s.now().Unix()
	s.roster[peer] = e
	return s.saveRosterLocked()
}

func (s *Store) DingFresh(peer a2al.Address) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.roster[peer]
	if !ok || e.DingAt == 0 {
		return false
	}
	return s.now().Unix()-e.DingAt < int64(DingMerge/time.Second)
}

func (s *Store) CanSend(peer a2al.Address) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	e, ok := s.roster[peer]
	return ok && (e.State == StateOutPending || e.State == StateMutual)
}

func (s *Store) AppendOut(peer a2al.Address, rec Rec) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	e, ok := s.roster[peer]
	if !ok || (e.State != StateOutPending && e.State != StateMutual) {
		return 0, ErrNotFriends
	}
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return 0, err
	}
	if pl.next == 0 {
		pl.next = 1
	}
	rec.Seq = pl.next
	pl.next++
	rec.Dir = DirOut
	if rec.TS == 0 {
		rec.TS = s.now().UnixMilli()
	}
	rec.Status = StatusLocal
	pl.recs = append(pl.recs, rec)
	if err := s.saveLogLocked(peer, pl); err != nil {
		return 0, err
	}
	return rec.Seq, nil
}

func (s *Store) AppendIn(peer a2al.Address, rec Rec) (dup bool, unreadEdge bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.unreadLocked(peer)
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return false, false, err
	}
	author := rec.Author
	if author == (a2al.Address{}) {
		author = peer
	}
	for _, r := range pl.recs {
		if r.Dir != DirIn || r.Seq != rec.Seq {
			continue
		}
		ra := r.Author
		if ra == (a2al.Address{}) {
			ra = peer
		}
		if ra == author {
			return true, false, nil
		}
	}
	rec.Dir = DirIn
	rec.Status = StatusIn
	if rec.TS == 0 {
		rec.TS = s.now().UnixMilli()
	}
	pl.recs = append(pl.recs, rec)
	if err := s.saveLogLocked(peer, pl); err != nil {
		return false, false, err
	}
	after := s.unreadLocked(peer)
	return false, before == 0 && after > 0, nil
}

func (s *Store) MarkSent(peer a2al.Address, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return err
	}
	for i := range pl.recs {
		if pl.recs[i].Dir == DirOut && pl.recs[i].Seq == seq {
			pl.recs[i].Status = StatusSent
			return s.saveLogLocked(peer, pl)
		}
	}
	return nil
}

func (s *Store) Unsent(peer a2al.Address) []Rec {
	s.mu.Lock()
	defer s.mu.Unlock()
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return nil
	}
	var out []Rec
	for _, r := range pl.recs {
		if r.Dir == DirOut && r.Status == StatusLocal {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) Read(peer a2al.Address, after uint64, limit int) (out []Rec, scannedTo uint64, hasMore bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return nil, after, false
	}
	n := len(pl.recs)
	start := int(after)
	if start < 0 {
		start = 0
	}
	if start > n {
		start = n
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	end := start + limit
	if end > n {
		end = n
	}
	out = make([]Rec, 0, end-start)
	for i := start; i < end; i++ {
		r := pl.recs[i]
		r.Idx = uint64(i + 1)
		out = append(out, r)
	}
	return out, uint64(end), end < n
}

func (s *Store) MaxInSeq(peer a2al.Address) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	pl, err := s.loadLogLocked(peer)
	if err != nil {
		return 0
	}
	var max uint64
	for _, r := range pl.recs {
		if r.Dir == DirIn && r.Seq > max {
			max = r.Seq
		}
	}
	return max
}

func (s *Store) sweepLocked() {
	now := s.now().Unix()
	cut := now - int64(IgnoreTTL/time.Second)
	changed := false
	for peer, e := range s.roster {
		if e.State == StateInPending && e.Since > 0 && e.Since < cut {
			delete(s.roster, peer)
			changed = true
		}
	}
	if changed {
		_ = s.saveRosterLocked()
	}
}

func (s *Store) rosterPath() string {
	return filepath.Join(s.dir, "roster.cbor")
}

func (s *Store) peerDir(peer a2al.Address) string {
	return filepath.Join(s.dir, "peers", hex.EncodeToString(peer[:]))
}

func (s *Store) logPath(peer a2al.Address) string {
	return filepath.Join(s.peerDir(peer), "log.cbor")
}

func (s *Store) loadRoster() error {
	b, err := os.ReadFile(s.rosterPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f rosterFile
	if err := cbor.Unmarshal(b, &f); err != nil {
		return err
	}
	for _, w := range f.Entries {
		if len(w.Peer) != len(a2al.Address{}) {
			continue
		}
		var peer a2al.Address
		copy(peer[:], w.Peer)
		s.roster[peer] = RosterEntry{Peer: peer, State: w.State, Since: w.Since, Note: w.Note, DingAt: w.DingAt, ReadIdx: w.ReadIdx}
	}
	return nil
}

func (s *Store) saveRosterLocked() error {
	f := rosterFile{Entries: make([]rosterWire, 0, len(s.roster))}
	for _, e := range s.roster {
		f.Entries = append(f.Entries, rosterWire{
			Peer:    e.Peer[:],
			State:   e.State,
			Since:   e.Since,
			Note:    e.Note,
			DingAt:  e.DingAt,
			ReadIdx: e.ReadIdx,
		})
	}
	return writeCBOR(s.rosterPath(), f)
}

func (s *Store) loadLogLocked(peer a2al.Address) (*peerLog, error) {
	if pl, ok := s.logs[peer]; ok {
		return pl, nil
	}
	pl := &peerLog{next: 1}
	b, err := os.ReadFile(s.logPath(peer))
	if err != nil {
		if os.IsNotExist(err) {
			s.logs[peer] = pl
			return pl, nil
		}
		return nil, err
	}
	var f logFile
	if err := cbor.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	pl.next = f.Next
	if pl.next == 0 {
		pl.next = 1
	}
	for _, w := range f.Recs {
		r := Rec{Seq: w.Seq, Dir: w.Dir, TS: w.TS, Kind: w.Kind, Body: w.Body, Name: w.Name, Size: w.Size, Status: w.Status, Grant: w.Grant}
		if len(w.Ref) == 32 {
			copy(r.Ref[:], w.Ref)
		}
		if len(w.Author) == len(a2al.Address{}) {
			copy(r.Author[:], w.Author)
		}
		pl.recs = append(pl.recs, r)
		if r.Dir == DirOut && r.Seq >= pl.next {
			pl.next = r.Seq + 1
		}
	}
	s.logs[peer] = pl
	return pl, nil
}

func (s *Store) saveLogLocked(peer a2al.Address, pl *peerLog) error {
	f := logFile{Next: pl.next, Recs: make([]recWire, 0, len(pl.recs))}
	for _, r := range pl.recs {
		w := recWire{Seq: r.Seq, Dir: r.Dir, TS: r.TS, Kind: r.Kind, Body: r.Body, Name: r.Name, Size: r.Size, Status: r.Status, Grant: r.Grant}
		if r.Ref != ([32]byte{}) {
			w.Ref = r.Ref[:]
		}
		if r.Author != (a2al.Address{}) {
			w.Author = r.Author[:]
		}
		f.Recs = append(f.Recs, w)
	}
	if err := os.MkdirAll(s.peerDir(peer), 0o700); err != nil {
		return err
	}
	return writeCBOR(s.logPath(peer), f)
}

func writeCBOR(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := cbor.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func TruncateRunes(s string, n int) string {
	if n <= 0 || s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
