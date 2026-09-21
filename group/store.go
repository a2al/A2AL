// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/a2al/a2al"
)

// logFileName is the append-only log file that stores all entries sequentially.
const logFileName = "entries.log"

// logHeaderSize is the byte length of each record's header: 4B length + 4B CRC32.
const logHeaderSize = 8

// entryMeta is the in-memory index record for a single locally-stored entry.
// All fields needed for filtering, membership replay, and pagination are kept
// here; the full CBOR bytes (including body) live only on disk.
type entryMeta struct {
	ID      [32]byte
	TS      int64
	Author  a2al.Address
	Kind    string
	ReplyTo [32]byte
	To      []a2al.Address
	Parents [][32]byte
	// Location of the CBOR payload in entries.log.
	offset int64 // byte offset of the CBOR data (immediately after the 8-byte header)
	size   int32 // byte length of the CBOR data
}

// ReadFilter provides optional filtering criteria for Read.
// Zero value means "no constraint on this field".
type ReadFilter struct {
	Kind    string       // match exact kind string
	Author  a2al.Address // match exact author AID (zero = any)
	SinceTS int64        // TS >= SinceTS (0 = no lower bound)
	UntilTS int64        // TS <= UntilTS (0 = no upper bound)
	To      a2al.Address // entry must mention this AID in its To list (zero = any)
	ReplyTo [32]byte     // match exact ReplyTo entry ID (zero = any)
}

// matchesMeta returns true when all non-zero filter fields match em.
func (f ReadFilter) matchesMeta(em entryMeta) bool {
	if f.Kind != "" && em.Kind != f.Kind {
		return false
	}
	if f.Author != (a2al.Address{}) && em.Author != f.Author {
		return false
	}
	if f.SinceTS != 0 && em.TS < f.SinceTS {
		return false
	}
	if f.UntilTS != 0 && em.TS > f.UntilTS {
		return false
	}
	if f.To != (a2al.Address{}) {
		found := false
		for _, t := range em.To {
			if t == f.To {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.ReplyTo != ([32]byte{}) && em.ReplyTo != f.ReplyTo {
		return false
	}
	return true
}

// Store manages the local replica of a single Group.
//
// Storage layout (under dir):
//
//	meta.cbor      – Group identity and creation parameters (written once)
//	entries.log    – Append-only entry log; each record is [4B len][4B CRC32][CBOR]
//
// Objects are not stored here; a2ald maps hash→path in cas-map.json.
//
// In-memory state is rebuilt from entries.log on Open. Crash safety is achieved
// by a length-prefix + CRC32 per record: incomplete tail records are detected
// and truncated on next Open.
//
// All exported methods are safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	dir     string
	meta    Meta
	logPath string
	logFile *os.File // opened O_RDWR|O_CREATE; WriteAt is used for appending

	// Append position — updated under mu (write lock) after every Append.
	logEnd int64

	// In-memory index: entries[i] has local seq = i+1 (1-based).
	// The slice is only ever appended to; existing elements are immutable.
	entries []entryMeta
	byID    map[[32]byte]int      // entry ID → index in entries
	heads   map[[32]byte]struct{} // DAG leaf IDs (not yet referenced as parent)
	wanted  map[[32]byte]struct{} // parent IDs referenced but not yet stored locally

	// Cached membership state; invalidated whenever Append writes a new entry.
	membersOK  bool
	membersVal MemberSet

	// readCursor is the local-seq high-water mark indicating how far the owning
	// AID has read. Unread count = MaxSeq() - readCursor. This drives the
	// edge-triggered group.unread event (0→>0 transition only). Persisted to
	// "cursor" in the store directory; zero means "nothing read yet".
	readCursor uint64
}

const cursorFileName = "cursor"

// ReadCursor returns the current read-cursor value (0 = nothing read).
func (s *Store) ReadCursor() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readCursor
}

// AdvanceCursor sets the read cursor to seq if seq > current cursor.
// It is a no-op when seq ≤ current cursor. Persists immediately.
// Returns true when the cursor actually advanced.
func (s *Store) AdvanceCursor(seq uint64) (advanced bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.readCursor {
		return false, nil
	}
	if err := s.writeCursorLocked(seq); err != nil {
		return false, err
	}
	s.readCursor = seq
	return true, nil
}

// UnreadCount returns how many entries past the read cursor were written by
// someone other than self.
//
// An AID's own entries are never unread to itself. Counting them would force
// the cursor to be advanced on every self-write just to keep the count honest,
// and that advance would silently swallow entries other members wrote in the
// meantime — the author would stop being notified about everyone else.
func (s *Store) UnreadCount(self a2al.Address) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unreadCountLocked(self, s.MaxSeqLocked())
}

// UnreadCountUpTo is UnreadCount restricted to entries with seq ≤ upToSeq.
// Callers use it to reconstruct the unread count as of an earlier moment,
// which is what makes the group.unread edge (0 → >0) computable.
func (s *Store) UnreadCountUpTo(self a2al.Address, upToSeq uint64) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unreadCountLocked(self, upToSeq)
}

// unreadCountLocked counts non-self entries in (readCursor, upToSeq].
// entries[i] has seq i+1, so the scan starts at index readCursor.
func (s *Store) unreadCountLocked(self a2al.Address, upToSeq uint64) uint64 {
	if upToSeq > s.MaxSeqLocked() {
		upToSeq = s.MaxSeqLocked()
	}
	if upToSeq <= s.readCursor {
		return 0
	}
	var n uint64
	for i := int(s.readCursor); i < int(upToSeq); i++ {
		if s.entries[i].Author != self {
			n++
		}
	}
	return n
}

// MaxSeqLocked returns MaxSeq without acquiring the read lock.
// Must be called while already holding s.mu (read or write).
func (s *Store) MaxSeqLocked() uint64 {
	return uint64(len(s.entries))
}

func (s *Store) writeCursorLocked(seq uint64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], seq)
	return os.WriteFile(filepath.Join(s.dir, cursorFileName), buf[:], 0o600)
}

func (s *Store) loadCursor() {
	b, err := os.ReadFile(filepath.Join(s.dir, cursorFileName))
	if err != nil || len(b) < 8 {
		s.readCursor = 0
		return
	}
	s.readCursor = binary.LittleEndian.Uint64(b)
}

// Create initialises a new Group store in dir and returns the opened Store.
func Create(dir string, priv ed25519.PrivateKey, creator a2al.Address, title string) (*Store, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	if isGroupDir(dir) {
		return nil, errors.New("group: directory already contains a group store")
	}

	id, err := newGroupID(creator)
	if err != nil {
		return nil, err
	}
	m := Meta{
		SchemaVersion: schemaVersion,
		GroupID:       id,
		CreatorAID:    creator,
		Title:         title,
		CreatedAt:     nowUnix(),
	}
	if err := writeMeta(dir, m); err != nil {
		return nil, err
	}

	s, err := openStore(dir, m)
	if err != nil {
		return nil, err
	}

	// Genesis entry: meta entry carrying the group title.
	genesis, err := NewEntry(priv, creator, nil, KindMeta, WithBody([]byte(title)))
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.appendEntry(genesis); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Open loads an existing Group store from dir.
func Open(dir string) (*Store, error) {
	if !isGroupDir(dir) {
		return nil, ErrNoStore
	}
	m, err := readMeta(dir)
	if err != nil {
		return nil, err
	}
	return openStore(dir, m)
}

// openStore opens (or creates) entries.log and builds the in-memory index.
func openStore(dir string, m Meta) (*Store, error) {
	logPath := filepath.Join(dir, logFileName)
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("group: open log: %w", err)
	}
	s := &Store{
		dir:     dir,
		meta:    m,
		logPath: logPath,
		logFile: f,
		byID:    make(map[[32]byte]int),
		heads:   make(map[[32]byte]struct{}),
		wanted:  make(map[[32]byte]struct{}),
	}
	if err := s.loadLog(); err != nil {
		_ = f.Close()
		return nil, err
	}
	s.loadCursor()
	return s, nil
}

// Close releases the log file handle. The Store must not be used after Close.
func (s *Store) Close() error {
	if s.logFile != nil {
		return s.logFile.Close()
	}
	return nil
}

// loadLog scans entries.log and builds the in-memory index.
// Incomplete tail records (from a crash mid-write) are detected via CRC and
// truncated so the store is always in a consistent state after Open.
func (s *Store) loadLog() error {
	info, err := s.logFile.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()
	if fileSize == 0 {
		s.logEnd = 0
		return nil
	}

	var pos int64
	var lastGoodPos int64
	var hdr [logHeaderSize]byte

	for pos < fileSize {
		if _, err := s.logFile.ReadAt(hdr[:], pos); err != nil {
			break // short read at end → truncate to lastGoodPos
		}
		payloadLen := int(binary.BigEndian.Uint32(hdr[:4]))
		expectedCRC := binary.BigEndian.Uint32(hdr[4:8])

		// Sanity-check header values before allocating.
		if payloadLen <= 0 || payloadLen > 8*1024*1024 {
			break // corrupt header
		}
		end := pos + logHeaderSize + int64(payloadLen)
		if end > fileSize {
			break // payload extends beyond EOF → incomplete write
		}

		payload := make([]byte, payloadLen)
		if _, err := s.logFile.ReadAt(payload, pos+logHeaderSize); err != nil {
			break // short read
		}
		if crc32.ChecksumIEEE(payload) != expectedCRC {
			break // corrupt payload
		}

		e, err := Unmarshal(payload)
		if err != nil {
			break // invalid CBOR
		}

		// Record is valid: add to index.
		em := entryMeta{
			ID:      e.ID,
			TS:      e.TS,
			Author:  e.Author,
			Kind:    e.Kind,
			ReplyTo: e.ReplyTo,
			To:      e.To,
			Parents: e.Parents,
			offset:  pos + logHeaderSize,
			size:    int32(payloadLen),
		}
		idx := len(s.entries)
		s.entries = append(s.entries, em)
		s.byID[e.ID] = idx
		s.heads[e.ID] = struct{}{}
		for _, p := range e.Parents {
			delete(s.heads, p)
			if _, ok := s.byID[p]; !ok {
				s.wanted[p] = struct{}{}
			}
		}
		delete(s.wanted, e.ID)

		lastGoodPos = end
		pos = end
	}

	// Truncate file to remove any incomplete tail record.
	if lastGoodPos < fileSize {
		if err := s.logFile.Truncate(lastGoodPos); err != nil {
			return fmt.Errorf("group: truncate corrupt log tail: %w", err)
		}
	}
	s.logEnd = lastGoodPos
	return nil
}

// --- write path ---

// appendLogRecord writes [4B len][4B CRC32][payload] to the log using WriteAt,
// which is positioned and does not require the file seek position to be at the end.
// Returns the byte offset of the payload (immediately after the 8-byte header).
// Caller must hold s.mu (write lock).
func (s *Store) appendLogRecord(payload []byte) (int64, error) {
	var hdr [logHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))

	// Write header + payload as a single buffer to minimise partial-write risk.
	buf := make([]byte, logHeaderSize+len(payload))
	copy(buf[:logHeaderSize], hdr[:])
	copy(buf[logHeaderSize:], payload)

	dataOffset := s.logEnd + logHeaderSize
	if _, err := s.logFile.WriteAt(buf, s.logEnd); err != nil {
		return 0, err
	}
	s.logEnd += int64(len(buf))
	return dataOffset, nil
}

// appendEntry marshals e, writes it to the log, and updates the in-memory index.
// Caller must hold s.mu (write lock).
func (s *Store) appendEntry(e Entry) error {
	payload, err := e.Marshal()
	if err != nil {
		return err
	}
	offset, err := s.appendLogRecord(payload)
	if err != nil {
		return err
	}

	em := entryMeta{
		ID:      e.ID,
		TS:      e.TS,
		Author:  e.Author,
		Kind:    e.Kind,
		ReplyTo: e.ReplyTo,
		To:      e.To,
		Parents: e.Parents,
		offset:  offset,
		size:    int32(len(payload)),
	}
	idx := len(s.entries)
	s.entries = append(s.entries, em)
	s.byID[e.ID] = idx
	s.heads[e.ID] = struct{}{}
	for _, p := range e.Parents {
		delete(s.heads, p)
		if _, ok := s.byID[p]; !ok {
			s.wanted[p] = struct{}{}
		}
	}
	delete(s.wanted, e.ID)
	s.membersOK = false // invalidate members cache
	return nil
}

// --- public API ---

// ID returns the group's persistent identifier.
func (s *Store) ID() [32]byte { return s.meta.GroupID }

// Meta returns a copy of the group's metadata.
func (s *Store) Meta() Meta { return s.meta }

// Append validates and persists a signed entry.
//
// If pub is non-nil, the entry's signature and ID are verified against it.
// Pass nil only for entries created locally (already verified by the caller).
//
// If the entry ID is already known, Append is idempotent (returns nil).
// Parents do not need to be locally present; out-of-order sync is supported.
func (s *Store) Append(e Entry, pub ed25519.PublicKey) error {
	if len(e.Body) > MaxEntryBodySize {
		return fmt.Errorf("group: entry body %d bytes exceeds protocol limit of %d bytes; use Ref + object instead",
			len(e.Body), MaxEntryBodySize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[e.ID]; exists {
		return nil // idempotent
	}
	if pub != nil {
		if err := e.Verify(pub); err != nil {
			return err
		}
	}
	return s.appendEntry(e)
}

// MaxEntryBodySize mirrors protocol.MaxEntryBodySize and is the maximum allowed
// byte length of an inline entry body.  Defined here to avoid importing the
// protocol package from the core group library.  The value MUST match
// protocol.MaxEntryBodySize; a test in group_sync enforces this.
const MaxEntryBodySize = 2048

// Heads returns the current DAG leaf entry IDs.
func (s *Store) Heads() [][32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([][32]byte, 0, len(s.heads))
	for id := range s.heads {
		out = append(out, id)
	}
	return out
}

// EntryCount returns the total number of locally-stored entries.
func (s *Store) EntryCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// MaxSeq returns the local arrival sequence number of the most recently stored
// entry. Seq is 1-based; 0 means the store is empty.
// Used by the unread-count calculation: unread = MaxSeq − readCursor.
func (s *Store) MaxSeq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.entries))
}

// LastEntryTS returns the TS of the most recently stored entry, or 0 if empty.
func (s *Store) LastEntryTS() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return 0
	}
	return s.entries[len(s.entries)-1].TS
}

// Get retrieves an entry by ID. Returns (Entry{}, false) if not locally present.
func (s *Store) Get(id [32]byte) (Entry, bool) {
	s.mu.RLock()
	idx, ok := s.byID[id]
	if !ok {
		s.mu.RUnlock()
		return Entry{}, false
	}
	em := s.entries[idx]
	s.mu.RUnlock()

	e, err := s.readEntryAt(em.offset, em.size)
	if err != nil {
		return Entry{}, false
	}
	return e, true
}

// Missing returns the IDs from peerHeads that are not locally known.
func (s *Store) Missing(peerHeads [][32]byte) [][32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out [][32]byte
	for _, id := range peerHeads {
		if _, ok := s.byID[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

// WantedParents returns parent IDs referenced by local entries but not yet
// stored locally. These should be included in the next Want request.
func (s *Store) WantedParents() [][32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.wanted) == 0 {
		return nil
	}
	out := make([][32]byte, 0, len(s.wanted))
	for id := range s.wanted {
		out = append(out, id)
	}
	return out
}

// Closure computes the Give payload for a sync session.
//
// Returns all locally-stored entries reachable from fromIDs but not from
// peerKnownHeads, capped at 200 entries per call.
func (s *Store) Closure(fromIDs, peerKnownHeads [][32]byte) ([]Entry, error) {
	// Snapshot the index under read lock; disk I/O is lock-free.
	s.mu.RLock()
	snapshotIDs := make(map[[32]byte]int, len(s.byID))
	for id, idx := range s.byID {
		snapshotIDs[id] = idx
	}
	snapshotMeta := make([]entryMeta, len(s.entries))
	copy(snapshotMeta, s.entries)
	s.mu.RUnlock()

	// BFS from peerKnownHeads: mark entries the peer already has.
	peerKnown := make(map[[32]byte]struct{})
	queue := append([][32]byte{}, peerKnownHeads...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, seen := peerKnown[id]; seen {
			continue
		}
		peerKnown[id] = struct{}{}
		if idx, ok := snapshotIDs[id]; ok {
			queue = append(queue, snapshotMeta[idx].Parents...)
		}
	}

	// BFS from fromIDs: collect entries the peer needs.
	const maxEntries = 200
	needed := make(map[[32]byte]struct{})
	queue = append([][32]byte{}, fromIDs...)
	for len(queue) > 0 && len(needed) < maxEntries {
		id := queue[0]
		queue = queue[1:]
		if _, skip := peerKnown[id]; skip {
			continue
		}
		if _, seen := needed[id]; seen {
			continue
		}
		idx, ok := snapshotIDs[id]
		if !ok {
			continue
		}
		needed[id] = struct{}{}
		queue = append(queue, snapshotMeta[idx].Parents...)
	}

	out := make([]Entry, 0, len(needed))
	for id := range needed {
		idx := snapshotIDs[id]
		em := snapshotMeta[idx]
		e, err := s.readEntryAt(em.offset, em.size)
		if err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// Entries retrieves multiple entries by ID. IDs not locally known are skipped.
func (s *Store) Entries(ids [][32]byte) ([]Entry, error) {
	var out []Entry
	for _, id := range ids {
		if e, ok := s.Get(id); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// EntryRead pairs an Entry with its local arrival sequence number.
//
// Seq is 1-based, monotonically increasing, and stable: it reflects the order
// entries were stored locally and never changes once assigned, even when
// late-arriving entries are inserted before earlier ones in causal order.
// Clients use Seq as a stable row identifier and as a start point to read
// from; to page forward they use the scannedTo returned by Read, which also
// accounts for entries the filter skipped. This mirrors the Kafka "offset"
// convention for append-only logs.
type EntryRead struct {
	Entry
	Seq uint64
}

// Read returns entries in causal display order, starting after afterSeq.
//
//   - afterSeq=0 means "from the beginning".
//   - Only entries satisfying filter are returned (all fields zero = no filter).
//   - At most limit entries are returned (default 50 if limit ≤ 0).
//   - scannedTo is how far this call examined: the seq of the last returned
//     entry when the page hit the limit, otherwise the end of the log (the scan
//     proved nothing further matches). Callers page forward by passing it as
//     afterSeq. It is deliberately not derivable from the returned entries — a
//     filtered read examines far past its last match, and a caller that instead
//     resumes from that match re-walks the unmatched tail on every call.
//   - hasMore is true only when the page was truncated by limit. A filtered read
//     that scanned to the end reports false even if later entries exist, because
//     none of them match.
//
// Each returned EntryRead carries its Seq so callers can correlate display
// rows with positions without counting. Within each page entries are sorted
// in causal (topological) order; Seq values reflect arrival order and may
// therefore not be monotone within the page when concurrent writes occur.
func (s *Store) Read(afterSeq uint64, limit int, filter ReadFilter) ([]EntryRead, uint64, bool, error) {
	if limit <= 0 {
		limit = 50
	}

	s.mu.RLock()
	startIdx := int(afterSeq) // seq is 1-based, so afterSeq=N means start at index N
	total := len(s.entries)
	if startIdx >= total {
		s.mu.RUnlock()
		return nil, afterSeq, false, nil
	}

	// Collect matching index entries up to limit.
	var matchIdxs []int
	for i := startIdx; i < total; i++ {
		if filter.matchesMeta(s.entries[i]) {
			matchIdxs = append(matchIdxs, i)
			if len(matchIdxs) == limit {
				break
			}
		}
	}

	// hasMore means "the page was cut short", i.e. the scan stopped on the limit
	// rather than running off the end. Deriving it from the last match instead
	// would report more pages whenever a filter's last hit is not the newest
	// entry in the log — true for almost every filtered read, and the reason two
	// replicas holding identical data disagreed on it.
	hasMore := len(matchIdxs) == limit
	scannedTo := afterSeq
	if len(matchIdxs) > 0 {
		scannedTo = uint64(matchIdxs[len(matchIdxs)-1] + 1) // seq is 1-based
	}
	if !hasMore {
		// Scan reached the end: report that, so the next call does not re-walk
		// entries already known not to match.
		scannedTo = uint64(total)
	}

	// Copy metadata for disk reads, preserving seq per index (avoid holding lock during I/O).
	type seqMeta struct {
		em  entryMeta
		seq uint64 // arrival seq = index + 1
	}
	pairs := make([]seqMeta, len(matchIdxs))
	for i, idx := range matchIdxs {
		pairs[i] = seqMeta{em: s.entries[idx], seq: uint64(idx + 1)}
	}
	s.mu.RUnlock()

	// Read full entries from disk, building an id→seq map for recovery after sort.
	seqByID := make(map[[32]byte]uint64, len(pairs))
	raw := make([]Entry, 0, len(pairs))
	for _, p := range pairs {
		e, err := s.readEntryAt(p.em.offset, p.em.size)
		if err != nil {
			continue
		}
		seqByID[e.ID] = p.seq
		raw = append(raw, e)
	}

	// Sort within the page by causal order for display, then re-attach seqs.
	sorted := TopoSort(raw)
	out := make([]EntryRead, len(sorted))
	for i, e := range sorted {
		out[i] = EntryRead{Entry: e, Seq: seqByID[e.ID]}
	}
	return out, scannedTo, hasMore, nil
}

// Members returns the current membership state by replaying the entry log.
// The result is cached and invalidated whenever Append writes a new entry.
func (s *Store) Members() (MemberSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.membersOK {
		return s.membersVal, nil
	}
	ms, err := s.replayMembersFromLog()
	if err != nil {
		return MemberSet{}, err
	}
	s.membersVal = ms
	s.membersOK = true
	return ms, nil
}

// replayMembersFromLog reads membership-relevant entries from disk in seq order
// and replays them into a fresh MemberSet.
// Caller must hold s.mu (write lock is required to update the cache; this helper
// only reads disk and does not modify shared state).
func (s *Store) replayMembersFromLog() (MemberSet, error) {
	ms := MemberSet{members: make(map[a2al.Address]MemberRole)}
	ms.members[s.meta.CreatorAID] = RoleCreator

	for _, em := range s.entries {
		// For membership-affecting kinds, we need the entry's body.
		needsBody := em.Kind == KindMeta ||
			em.Kind == KindInvite ||
			em.Kind == KindRevoke ||
			em.Kind == KindGrantAdmin ||
			em.Kind == KindRevokeAdmin ||
			em.Kind == KindProposeInvite

		e := Entry{
			ID:      em.ID,
			Author:  em.Author,
			Kind:    em.Kind,
			TS:      em.TS,
			Parents: em.Parents,
			ReplyTo: em.ReplyTo,
			To:      em.To,
		}
		if needsBody {
			if full, err := s.readEntryAt(em.offset, em.size); err == nil {
				e.Body = full.Body
				e.Ref = full.Ref
			}
		}
		ms.Apply(e, s.meta.CreatorAID)
	}
	return ms, nil
}

// Balance returns the cost balance (total budgeted minus total spent) for aid.
func (s *Store) Balance(aid a2al.Address) (int64, error) {
	s.mu.RLock()
	metas := make([]entryMeta, len(s.entries))
	copy(metas, s.entries)
	s.mu.RUnlock()

	var relevant []Entry
	for _, em := range metas {
		if em.Kind != KindBudget && em.Kind != KindSpend {
			continue
		}
		e, err := s.readEntryAt(em.offset, em.size)
		if err != nil {
			continue
		}
		relevant = append(relevant, e)
	}
	return computeBalance(relevant, aid), nil
}

// RebuildDerived re-scans entries.log and rebuilds the in-memory index.
// Use after manual file manipulation or to recover from an inconsistency.
func (s *Store) RebuildDerived() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
	s.byID = make(map[[32]byte]int)
	s.heads = make(map[[32]byte]struct{})
	s.wanted = make(map[[32]byte]struct{})
	s.membersOK = false
	s.logEnd = 0
	return s.loadLog()
}

// --- internal helpers ---

// readEntryAt reads the CBOR payload at the given log position and unmarshals it.
// This uses ReadAt and does not affect the write position or require the lock.
func (s *Store) readEntryAt(offset int64, size int32) (Entry, error) {
	buf := make([]byte, size)
	if _, err := s.logFile.ReadAt(buf, offset); err != nil {
		return Entry{}, fmt.Errorf("group: read entry at %d: %w", offset, err)
	}
	return Unmarshal(buf)
}

// --- legacy format helpers (used only during migration) ---

// legacyListEntryIDs scans the old entries/{ab}/{62hex} directory layout and
// returns all entry IDs found. Used by GroupManager.MigrateFromLegacy.
func legacyListEntryIDs(dir string) ([][32]byte, error) {
	entriesDir := filepath.Join(dir, "entries")
	subdirs, err := os.ReadDir(entriesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids [][32]byte
	for _, sub := range subdirs {
		if !sub.IsDir() || len(sub.Name()) != 2 {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(entriesDir, sub.Name()))
		for _, f := range files {
			h := sub.Name() + f.Name()
			if len(h) != 64 {
				continue
			}
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != 32 {
				continue
			}
			var id [32]byte
			copy(id[:], b)
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// legacyReadEntry reads a single entry file from the old per-file format.
func legacyReadEntry(dir string, id [32]byte) (Entry, error) {
	h := hex.EncodeToString(id[:])
	path := filepath.Join(dir, "entries", h[:2], h[2:])
	data, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, err
	}
	return Unmarshal(data)
}

// MigrateFromLegacy reads all entries from the old per-file format in dir and
// appends them (in causal order) to dst. dst must be a freshly created Store.
// Returns the number of entries migrated.
func MigrateFromLegacy(dst *Store, srcDir string) (int, error) {
	ids, err := legacyListEntryIDs(srcDir)
	if err != nil {
		return 0, err
	}

	entries := make([]Entry, 0, len(ids))
	for _, id := range ids {
		e, err := legacyReadEntry(srcDir, id)
		if err != nil {
			continue // best-effort
		}
		entries = append(entries, e)
	}

	// Sort entries causally before inserting.
	sorted := TopoSort(entries)
	n := 0
	for _, e := range sorted {
		if err := dst.Append(e, nil); err == nil {
			n++
		}
	}
	return n, nil
}

// --- sorting helpers (kept here; also used by group_sync.go) ---

// TopoSort returns entries sorted in causal (topological) order: every entry
// appears after all its locally-known parents. Concurrent entries (no causal
// relationship) are ordered by (TS asc, ID lex asc) as a deterministic tiebreaker.
//
// Parents absent from the input slice are treated as already satisfied.
func TopoSort(entries []Entry) []Entry {
	if len(entries) == 0 {
		return entries
	}
	byID := make(map[[32]byte]Entry, len(entries))
	for _, e := range entries {
		byID[e.ID] = e
	}

	inDeg := make(map[[32]byte]int, len(byID))
	children := make(map[[32]byte][][32]byte, len(byID))
	for id, e := range byID {
		if _, ok := inDeg[id]; !ok {
			inDeg[id] = 0
		}
		for _, p := range e.Parents {
			if _, local := byID[p]; local {
				inDeg[id]++
				children[p] = append(children[p], id)
			}
		}
	}

	ready := make([]Entry, 0, len(byID))
	for id, deg := range inDeg {
		if deg == 0 {
			ready = append(ready, byID[id])
		}
	}
	sortByTSAndID(ready)

	out := make([]Entry, 0, len(byID))
	for len(ready) > 0 {
		e := ready[0]
		ready = ready[1:]
		out = append(out, e)

		var newReady []Entry
		for _, cid := range children[e.ID] {
			inDeg[cid]--
			if inDeg[cid] == 0 {
				newReady = append(newReady, byID[cid])
			}
		}
		if len(newReady) > 0 {
			ready = append(ready, newReady...)
			sortByTSAndID(ready)
		}
	}
	return out
}

// sortByTSAndID sorts entries by (TS asc, ID lex asc).
func sortByTSAndID(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].TS != entries[j].TS {
			return entries[i].TS < entries[j].TS
		}
		return string(entries[i].ID[:]) < string(entries[j].ID[:])
	})
}
