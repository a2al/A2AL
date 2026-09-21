// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

const groupSyncTimeout = 30 * time.Second

// acceptGroupSync handles an inbound QUIC stream whose magic bytes "a2gp" have
// already been consumed by dispatchInboundStream.
//
// Wire layout (after magic):
//
//	[group_id 32B]           ← dialer identifies which group to sync
//	[frame…]…                ← bidirectional Have/Want/Give/Done frames
func (d *Daemon) acceptGroupSync(ac *host.AgentConn, str quic.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(groupSyncTimeout))

	// Read the group ID the dialer wants to sync.
	var groupID [32]byte
	if _, err := io.ReadFull(str, groupID[:]); err != nil {
		d.log.Debug("group sync: read group_id", "err", err)
		return
	}

	store, err := d.groups.Open(ac.Local, groupID)
	if err != nil {
		d.log.Debug("group sync: unknown group", "id", hex.EncodeToString(groupID[:4]), "err", err)
		return
	}

	// Member gate: only active/pending members may sync.
	// Strangers and revoked members are rejected.
	if memberSet, merr := store.Members(); merr == nil {
		if !memberSet.CanSync(ac.Remote) {
			d.log.Debug("group sync: non-member rejected",
				"group", hex.EncodeToString(groupID[:4]),
				"remote", ac.Remote.String(),
			)
			return
		}
	} else {
		d.log.Debug("group sync: member check error (permissive fallback)",
			"group", hex.EncodeToString(groupID[:4]),
			"err", merr,
		)
	}

	prevMaxSeq := store.MaxSeq() // snapshot before sync for edge-trigger calculation
	stats, err := runGroupSync(store, str, str)
	if err != nil {
		d.log.Debug("group sync: session error", "group", hex.EncodeToString(groupID[:4]), "err", err)
		return
	}
	newEntries := stats.Received
	// The peer dialled us: it is pulling from here, so we owe it low-latency
	// pushes while we hold center duty.
	d.notePeerPull(ac.Local, ac.Remote, groupID)
	d.notePeerRound(ac.Local, ac.Remote, groupID, stats)
	d.notePeerSync(ac.Local, ac.Remote, groupID)
	if newEntries > 0 {
		d.log.Debug("group sync: inbound complete", "group", hex.EncodeToString(groupID[:4]), "new", newEntries)
		// group.synced is a debug-level signal; do not surface to EventLog.
		// Unread/mention events are emitted by notifyGroupNewEntries below.
		d.notifyGroupNewEntries(ac.Local, groupID, store, prevMaxSeq)
	}
}

// SyncGroupWith opens an outbound QUIC stream to peerAID and runs one round of
// Group sync for groupID. localAID must be registered with this daemon.
//
// Returns the number of new entries received from the peer.
func (d *Daemon) SyncGroupWith(ctx context.Context, groupID [32]byte, localAID, peerAID a2al.Address) (int, error) {
	store, err := d.groups.Open(localAID, groupID)
	if err != nil {
		return 0, fmt.Errorf("group sync: open local store: %w", err)
	}

	// Resolve peerAID's current endpoints.
	er, err := d.resolveEndpoint(ctx, peerAID)
	if err != nil {
		return 0, fmt.Errorf("group sync: resolve peer %s: %w", peerAID.String(), err)
	}

	// Go through the pool rather than dialling directly: alignment
	// hits this path once per chosen member, and a fresh handshake each time is the
	// dominant cost. user=false so a dead peer gets a backoff record instead of
	// being re-dialled on every pass.
	conn, _, err := d.connPool.acquire(ctx, localAID, peerAID, er, false, false)
	if err != nil {
		return 0, fmt.Errorf("group sync: connect to peer: %w", err)
	}

	syncCtx, cancel := context.WithTimeout(ctx, groupSyncTimeout)
	defer cancel()

	open := func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		return c.OpenStreamSync(ctx)
	}
	conn, str, _, err := d.openPooled(syncCtx, localAID, peerAID, er, false, false, conn, open)
	if err != nil {
		return 0, fmt.Errorf("group sync: open stream: %w", err)
	}
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(groupSyncTimeout))

	// Send magic + group ID.
	if _, err := str.Write([]byte(protocol.MagicGroupSync)); err != nil {
		return 0, fmt.Errorf("group sync: write magic: %w", err)
	}
	if _, err := str.Write(groupID[:]); err != nil {
		return 0, fmt.Errorf("group sync: write group_id: %w", err)
	}

	prevMaxSeq := store.MaxSeq() // snapshot before sync rounds for edge-trigger calculation
	total := 0
	var syncErr error
	// Multi-round loop: continue syncing until no ancestor gaps remain.
	// Each round resolves at most 200 entries; a large quiet room may need
	// several rounds. Cap at 20 rounds to prevent infinite loops.
	const maxRounds = 20
	for round := 0; round < maxRounds; round++ {
		if round > 0 {
			// Re-open stream for subsequent rounds.
			str.Close()
			conn, str, _, err = d.openPooled(syncCtx, localAID, peerAID, er, false, false, conn, open)
			if err != nil {
				syncErr = fmt.Errorf("group sync: open continuation stream: %w", err)
				break
			}
			_ = str.SetDeadline(time.Now().Add(groupSyncTimeout))
			if _, err := str.Write([]byte(protocol.MagicGroupSync)); err != nil {
				syncErr = fmt.Errorf("group sync: write continuation magic: %w", err)
				break
			}
			if _, err := str.Write(groupID[:]); err != nil {
				syncErr = fmt.Errorf("group sync: write continuation group_id: %w", err)
				break
			}
		}

		stats, serr := runGroupSync(store, str, str)
		if serr != nil {
			str.Close()
			syncErr = serr
			break
		}
		total += stats.Received
		d.notePeerRound(localAID, peerAID, groupID, stats)

		// Stop if there are no more ancestor gaps and no new entries arrived.
		if stats.Received == 0 || len(store.WantedParents()) == 0 {
			str.Close()
			break
		}
		if round == maxRounds-1 {
			syncErr = errors.New("group sync: did not converge within 20 rounds")
		}
	}

	if total > 0 {
		d.log.Debug("group sync: outbound complete",
			"group", hex.EncodeToString(groupID[:4]),
			"peer", peerAID.String(),
			"new", total,
		)
	}
	if total > 0 {
		d.notifyGroupNewEntries(localAID, groupID, store, prevMaxSeq)
	}
	if syncErr != nil {
		if total > 0 {
			d.notePeerSync(localAID, peerAID, groupID)
		}
		return total, syncErr
	}
	d.notePeerSync(localAID, peerAID, groupID)
	return total, nil
}

type groupSyncStats struct {
	Received int
	Sent     int
	PeerHave uint64
	// LocalHave is our own entry count as advertised in this round's Have.
	// After a round completes the peer holds at least this much, which is the
	// only delivery inference we allow ourselves to make.
	LocalHave uint64
}

// runGroupSync executes one Have/Want/Give round over r/w.
func runGroupSync(store *group.Store, r io.Reader, w io.Writer) (groupSyncStats, error) {
	var zero groupSyncStats
	heads := store.Heads()
	localHave := uint64(store.EntryCount())
	if err := protocol.WriteGroupHave(w, heads, localHave); err != nil {
		return zero, fmt.Errorf("group sync: send have: %w", err)
	}

	// Step 2: read peer's Have, compute missing, send Want or Done.
	ft, peerHave, _, _, err := protocol.ReadGroupFrame(r)
	if err != nil {
		// EOF here typically means the peer closed the stream immediately because
		// it does not have a replica for this group.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return zero, fmt.Errorf("group sync: peer has no replica for this group (or group unknown): %w", err)
		}
		return zero, fmt.Errorf("group sync: read peer have: %w", err)
	}
	if ft != protocol.FrameTypeGroupHave {
		return zero, fmt.Errorf("group sync: expected Have frame, got 0x%02x", ft)
	}
	out := groupSyncStats{PeerHave: peerHave.EntryCount, LocalHave: localHave}

	// Want = new heads missing locally + any orphaned ancestors from prior partial syncs.
	missing := store.Missing(peerHave.Heads)
	missing = appendUniqIDs(missing, store.WantedParents())
	if len(missing) > 0 {
		if err := protocol.WriteGroupWant(w, missing); err != nil {
			return out, fmt.Errorf("group sync: send want: %w", err)
		}
	} else {
		if err := protocol.WriteGroupDone(w); err != nil {
			return out, fmt.Errorf("group sync: send done: %w", err)
		}
	}

	// Step 3: read peer's Want/Done, respond with Give.
	// Give uses Closure so that transitive ancestors are included in a single
	// round — preventing "orphaned ancestor" gaps in the peer's DAG.
	ft, _, peerWant, _, err := protocol.ReadGroupFrame(r)
	if err != nil {
		return out, fmt.Errorf("group sync: read peer want/done: %w", err)
	}
	switch ft {
	case protocol.FrameTypeGroupWant:
		entries, err := store.Closure(peerWant.IDs, peerHave.Heads)
		if err != nil {
			return out, fmt.Errorf("group sync: build closure for give: %w", err)
		}
		raw := make([][]byte, 0, len(entries))
		for _, e := range entries {
			b, merr := e.Marshal()
			if merr != nil {
				continue
			}
			raw = append(raw, b)
			out.Sent++
		}
		if err := protocol.WriteGroupGive(w, raw); err != nil {
			return out, fmt.Errorf("group sync: send give: %w", err)
		}
	case protocol.FrameTypeGroupDone:
		if err := protocol.WriteGroupGive(w, nil); err != nil {
			return out, fmt.Errorf("group sync: send empty give: %w", err)
		}
	default:
		return out, fmt.Errorf("group sync: unexpected frame 0x%02x", ft)
	}

	if len(missing) == 0 {
		return out, nil
	}
	ft, _, _, peerGive, err := protocol.ReadGroupFrame(r)
	if err != nil {
		if err == io.EOF || err == io.ErrClosedPipe {
			return out, nil
		}
		return out, fmt.Errorf("group sync: read give: %w", err)
	}
	if ft != protocol.FrameTypeGroupGive {
		return out, fmt.Errorf("group sync: expected Give frame, got 0x%02x", ft)
	}

	// Decode and filter entries before applying them.
	decoded := make([]group.Entry, 0, len(peerGive.Entries))
	for _, raw := range peerGive.Entries {
		e, uerr := group.Unmarshal(raw)
		if uerr != nil {
			continue
		}
		// Reject entries whose content does not hash to their claimed ID.
		// Pure local check; detects corruption and malformed payloads.
		if e.VerifyID() != nil {
			continue
		}
		decoded = append(decoded, e)
	}

	// Sort batch in causal order so incremental member checks are correct:
	// an invite entry will always be processed before the entries it authorises.
	decoded = group.TopoSort(decoded)

	// Validate author membership and apply incrementally.
	// Full signature verification is deferred (requires DHT pubkey lookup).
	memberSet, _ := store.Members()
	creatorAID := store.Meta().CreatorAID
	for _, e := range decoded {
		// For permission-affecting entry kinds, reject authors that are not
		// currently active members. Regular content entries are accepted
		// permissively — a new member's first message may arrive before all
		// callers have replayed the invite that granted them membership.
		if memberSet.Role(e.Author) < group.RoleMember {
			switch e.Kind {
			case group.KindInvite, group.KindRevoke, group.KindGrantAdmin,
				group.KindRevokeAdmin, group.KindBudget:
				continue // rejected: unknown or revoked author cannot affect shared state
			}
		}
		before := store.EntryCount()
		if aerr := store.Append(e, nil); aerr != nil {
			continue
		}
		if store.EntryCount() > before {
			// Keep the in-memory member set in sync so subsequent entries
			// in this batch see the updated roles immediately.
			memberSet.Apply(e, creatorAID)
			out.Received++
		}
	}
	return out, nil
}

// resolveEndpoint wraps the daemon's existing DHT resolve logic.
// Returns the peer's current EndpointRecord.
func (d *Daemon) resolveEndpoint(ctx context.Context, target a2al.Address) (*protocol.EndpointRecord, error) {
	return d.h.Resolve(ctx, target)
}

// appendUniqIDs appends elements of extra to base, skipping duplicates.
func appendUniqIDs(base, extra [][32]byte) [][32]byte {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[[32]byte]struct{}, len(base))
	for _, id := range base {
		seen[id] = struct{}{}
	}
	for _, id := range extra {
		if _, ok := seen[id]; !ok {
			base = append(base, id)
		}
	}
	return base
}

// syncGroupLocalPipe executes a bidirectional in-memory sync between two
// local group.Store replicas using paired io.Pipe connections.
// Both stores are mutually updated in a single call; neither side need be
// "server" or "client". Returns the total number of new entries written
// across both stores.
func syncGroupLocalPipe(fromStore, toStore *group.Store) (int, error) {
	// Both sides open with their own Have before reading the other's, so any
	// stream that can block a writer deadlocks them against each other. These
	// buffer without bound; a local round is a handful of frames.
	aToB := newLocalStream()
	bToA := newLocalStream()

	var nA, nB int
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)

	// fromStore reads from bToA, writes to aToB.
	go func() {
		defer wg.Done()
		st, err := runGroupSync(fromStore, bToA, aToB)
		nA, errA = st.Received, err
		aToB.Close()
	}()

	// toStore reads from aToB, writes to bToA.
	go func() {
		defer wg.Done()
		st, err := runGroupSync(toStore, aToB, bToA)
		nB, errB = st.Received, err
		bToA.Close()
	}()

	wg.Wait()
	// Report failures instead of swallowing them: a silent error here reads as
	// a successful round, which clears the peer's failure mark and lets the
	// information backoff slide all the way to 2m while nothing is syncing.
	return nA + nB, errors.Join(errA, errB)
}

// localStream is a one-way in-process byte stream that never blocks its
// writer. Readers block until data arrives or the writer closes.
type localStream struct {
	mu     sync.Mutex
	more   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newLocalStream() *localStream {
	s := &localStream{}
	s.more = sync.NewCond(&s.mu)
	return s
}

func (s *localStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := s.buf.Write(p)
	s.more.Broadcast()
	return n, err
}

func (s *localStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.buf.Len() == 0 {
		if s.closed {
			return 0, io.EOF
		}
		s.more.Wait()
	}
	return s.buf.Read(p)
}

// Close ends the stream for both sides; buffered data stays readable.
func (s *localStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.more.Broadcast()
	s.mu.Unlock()
	return nil
}

// notifyGroupNewEntries emits group.unread / group.mentioned events for a
// local AID after new entries have been stored in its replica. This is the
// shared helper called from local pipe, inbound, and outbound a2gp paths.
//
// prevMaxSeq is the store's MaxSeq **before** the new entries arrived.
// group.unread is edge-triggered: fires only when the unread count transitions
// from 0 to >0 (i.e. the store was fully read before this batch). Passing
// prevMaxSeq lets us determine the pre-arrival unread count without re-reading.
func (d *Daemon) notifyGroupNewEntries(localAID a2al.Address, groupID [32]byte, s *group.Store, prevMaxSeq uint64) {
	maxSeq := s.MaxSeq()
	if maxSeq <= prevMaxSeq {
		return // nothing arrived
	}
	d.noteAlignReceived(localAID, groupID)

	// Edge-trigger: fire group.unread only on the 0 → >0 transition, counting
	// only entries localAID did not write itself.
	before := s.UnreadCountUpTo(localAID, prevMaxSeq)
	now := s.UnreadCount(localAID)
	if before == 0 && now > 0 {
		d.bus.Publish(Event{
			Type: "group.unread",
			AID:  localAID,
			Data: map[string]any{
				"group_id":     hex.EncodeToString(groupID[:]),
				"unread_count": now,
			},
		})
	}

	// Emit group.mentioned for entries naming localAID. Scan only what just
	// arrived: scanning from the read cursor instead would re-announce every
	// still-unread mention on each sync round, which is how one entry ended up
	// producing six frames on a peer that synced six times.
	newEntries, _, _, err := s.Read(prevMaxSeq, int(maxSeq-prevMaxSeq), group.ReadFilter{To: localAID})
	if err != nil {
		return
	}
	for _, er := range newEntries {
		// Only emit mentioned for entries not authored by localAID itself.
		if er.Author == localAID {
			continue
		}
		d.bus.Publish(Event{
			Type: "group.mentioned",
			AID:  localAID,
			Data: map[string]any{
				"group_id": hex.EncodeToString(groupID[:]),
				"entry_id": hex.EncodeToString(er.ID[:]),
				"from":     er.Author.String(),
			},
		})
	}
}
