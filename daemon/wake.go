// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al"
)

const (
	wakeQuietDefault   = 2 * time.Second
	wakeMaxWaitDefault = 10 * time.Second
	wakeEventsCap      = 20
	wakeStoreFile      = "wake.json"
	wakeHandleToken    = "{{handle}}"
	wakeStderrCap      = 4096
	wakeCostUnitTokens = "tokens"
	wakeCostSourceACP  = "acp.session/update"
)

var wakeEventTypes = []string{
	"chat.received",
	"chat.invites",
	"group.mentioned",
	"mailbox.received",
}

type wakeBinding struct {
	AID        a2al.Address
	Via        string
	Cmd        string
	Args       []string
	Cwd        string
	SessionCwd string
	Cap        int64
}

type wakeLastResult struct {
	At           time.Time
	StartedAt    time.Time
	Ok           bool
	Error        string
	ExitCode     *int
	InFlight     bool
	PID          int
	SessionID    string
	Step         string
	Stderr       string
	StopReason   string
	CancelledFor string
	Cap          int64
	CapUnit      string
	Spend        int64
	SpendUnit    string
	Source       string
	ModelTag     string
}

type wakeDelivered struct {
	Peers      map[string]uint64 `json:"peers,omitempty"`
	Invites    []string          `json:"invites,omitempty"`
	HasInvites bool              `json:"has_invites,omitempty"`
	Groups     map[string]string `json:"groups,omitempty"`
	Mailbox    int               `json:"mailbox,omitempty"`
	HasMailbox bool              `json:"has_mailbox,omitempty"`
}

type wakeWindow struct {
	quiet   *time.Timer
	max     *time.Timer
	byPeer  map[string]wakePeerHit
	byGroup map[string]wakeGroupHit
	mailbox *wakeMailboxHit
	invites *wakeInvitesHit
}

type wakePeerHit struct {
	Peer string
	Seq  uint64
}

type wakeGroupHit struct {
	GroupID string
	EntryID string
	From    string
}

type wakeMailboxHit struct {
	Count int
}

type wakeInvitesHit struct {
	Count int
	Peers []string
}

type wakeScheduler struct {
	d         *Daemon
	mu        sync.Mutex
	bindings  map[a2al.Address]wakeBinding
	windows   map[a2al.Address]*wakeWindow
	last      map[a2al.Address]wakeLastResult
	handles   map[a2al.Address]string
	delivered map[a2al.Address]wakeDelivered
	outgoing  map[a2al.Address]wakeDelivered
	busy      map[a2al.Address]struct{}
	held      map[a2al.Address]*wakeWindow
	spawn     func(wakeBinding, []byte)
	quiet     time.Duration
	maxWait   time.Duration
	eventsCap int
}

func newWakeScheduler(d *Daemon) *wakeScheduler {
	s := &wakeScheduler{
		d:         d,
		bindings:  make(map[a2al.Address]wakeBinding),
		windows:   make(map[a2al.Address]*wakeWindow),
		last:      make(map[a2al.Address]wakeLastResult),
		handles:   make(map[a2al.Address]string),
		delivered: make(map[a2al.Address]wakeDelivered),
		outgoing:  make(map[a2al.Address]wakeDelivered),
		busy:      make(map[a2al.Address]struct{}),
		held:      make(map[a2al.Address]*wakeWindow),
		quiet:     wakeQuietDefault,
		maxWait:   wakeMaxWaitDefault,
		eventsCap: wakeEventsCap,
	}
	if d != nil {
		s.spawn = d.spawnWakeCommand
		s.loadFromDisk()
	}
	return s
}

func (d *Daemon) startWakeBridge(ctx context.Context) {
	if d == nil || d.wake == nil || d.bus == nil {
		return
	}
	ch, cancel := d.bus.Subscribe(Filter{Types: wakeEventTypes})
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				d.wake.stop()
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				d.wake.onEvent(evt)
			}
		}
	}()
}

func (s *wakeScheduler) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for aid, w := range s.windows {
		stopWakeWindow(w)
		delete(s.windows, aid)
	}
}

func (s *wakeScheduler) onEvent(evt Event) {
	if s == nil {
		return
	}
	if !wakeTriggerType(evt.Type) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[evt.AID]
	if !ok || b.Cmd == "" {
		return
	}
	w := s.windows[evt.AID]
	if w == nil {
		w = &wakeWindow{
			byPeer:  make(map[string]wakePeerHit),
			byGroup: make(map[string]wakeGroupHit),
		}
		s.windows[evt.AID] = w
		aid := evt.AID
		w.max = time.AfterFunc(s.maxWait, func() { s.fire(aid) })
	}
	mergeWakeEvent(w, evt)
	if w.quiet != nil {
		w.quiet.Stop()
	}
	aid := evt.AID
	w.quiet = time.AfterFunc(s.quiet, func() { s.fire(aid) })
}

func (s *wakeScheduler) fire(aid a2al.Address) {
	s.fireBatch(aid, false)
}

func (s *wakeScheduler) fireNow(aid a2al.Address) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	b, ok := s.bindings[aid]
	s.mu.Unlock()
	if !ok || b.Cmd == "" {
		return false
	}
	s.fireBatch(aid, true)
	return true
}

func (s *wakeScheduler) fireBatch(aid a2al.Address, skipDelivered bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	w := s.windows[aid]
	delete(s.windows, aid)
	if w != nil {
		stopWakeWindow(w)
	} else if skipDelivered {
		w = &wakeWindow{}
	} else {
		s.mu.Unlock()
		return
	}
	if _, busy := s.busy[aid]; busy {
		s.held[aid] = absorbWakeWindow(s.held[aid], w)
		s.mu.Unlock()
		return
	}
	batch := deliveredFromWindow(w)
	if !skipDelivered && !batch.exceeds(s.delivered[aid]) {
		s.mu.Unlock()
		return
	}
	b := s.bindings[aid]
	if b.Cmd == "" {
		s.mu.Unlock()
		return
	}
	s.busy[aid] = struct{}{}
	s.outgoing[aid] = batch
	payload := s.buildPayloadLocked(aid, w)
	spawn := s.spawn
	s.mu.Unlock()
	if spawn == nil {
		s.finishSpawn(aid)
		return
	}
	go func() {
		defer s.finishSpawn(aid)
		spawn(b, payload)
	}()
}

func (s *wakeScheduler) finishSpawn(aid a2al.Address) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.busy, aid)
	delete(s.outgoing, aid)
	held := s.held[aid]
	delete(s.held, aid)
	if held != nil {
		s.windows[aid] = held
	}
	s.mu.Unlock()
	if held != nil {
		s.fireBatch(aid, false)
	}
}

func stopWakeWindow(w *wakeWindow) {
	if w == nil {
		return
	}
	if w.quiet != nil {
		w.quiet.Stop()
	}
	if w.max != nil {
		w.max.Stop()
	}
}

func wakeTriggerType(typ string) bool {
	switch typ {
	case "chat.received", "chat.invites", "group.mentioned", "mailbox.received":
		return true
	default:
		return false
	}
}

func mergeWakeEvent(w *wakeWindow, evt Event) {
	m, _ := evt.Data.(map[string]any)
	switch evt.Type {
	case "chat.received":
		peer := mapString(m, "peer")
		if peer == "" {
			return
		}
		if w.byPeer == nil {
			w.byPeer = make(map[string]wakePeerHit)
		}
		w.byPeer[peer] = wakePeerHit{Peer: peer, Seq: mapUint64(m, "seq")}
	case "group.mentioned":
		gid := mapString(m, "group_id")
		if gid == "" {
			return
		}
		if w.byGroup == nil {
			w.byGroup = make(map[string]wakeGroupHit)
		}
		w.byGroup[gid] = wakeGroupHit{
			GroupID: gid,
			EntryID: mapString(m, "entry_id"),
			From:    mapString(m, "from"),
		}
	case "mailbox.received":
		n := int(mapUint64(m, "count"))
		if n <= 0 {
			n = 1
		}
		w.mailbox = &wakeMailboxHit{Count: n}
	case "chat.invites":
		hit := &wakeInvitesHit{Count: int(mapUint64(m, "count"))}
		if hit.Count <= 0 {
			hit.Count = 1
		}
		if raw, ok := m["peers"].([]string); ok {
			hit.Peers = append([]string(nil), raw...)
		} else if raw, ok := m["peers"].([]any); ok {
			for _, p := range raw {
				if s, ok := p.(string); ok && s != "" {
					hit.Peers = append(hit.Peers, s)
				}
			}
		}
		w.invites = hit
	}
}

type wakePayload struct {
	AID     string         `json:"aid"`
	Handle  string         `json:"handle,omitempty"`
	Pending map[string]any `json:"pending,omitempty"`
	Events  []wakeEvent    `json:"events"`
}

type wakeEvent struct {
	Type    string   `json:"type"`
	Peer    string   `json:"peer,omitempty"`
	Seq     uint64   `json:"seq,omitempty"`
	GroupID string   `json:"group_id,omitempty"`
	EntryID string   `json:"entry_id,omitempty"`
	From    string   `json:"from,omitempty"`
	Count   int      `json:"count,omitempty"`
	Peers   []string `json:"peers,omitempty"`
}

func (s *wakeScheduler) buildPayloadLocked(aid a2al.Address, w *wakeWindow) []byte {
	p := wakePayload{
		AID:    aid.String(),
		Events: s.collectEvents(w),
	}
	if h := s.handles[aid]; h != "" {
		p.Handle = h
	}
	if s.d != nil {
		if bag := s.d.pendingFor(aid); bag != nil {
			if inner, ok := bag[aid.String()].(map[string]any); ok && len(inner) > 0 {
				p.Pending = inner
			}
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return []byte(`{"aid":"` + aid.String() + `","events":[]}`)
	}
	return b
}

func (s *wakeScheduler) collectEvents(w *wakeWindow) []wakeEvent {
	if w == nil {
		return []wakeEvent{}
	}
	out := make([]wakeEvent, 0, len(w.byPeer)+len(w.byGroup)+2)
	peers := make([]string, 0, len(w.byPeer))
	for peer := range w.byPeer {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	for _, peer := range peers {
		h := w.byPeer[peer]
		out = append(out, wakeEvent{Type: "chat.received", Peer: h.Peer, Seq: h.Seq})
	}
	gids := make([]string, 0, len(w.byGroup))
	for gid := range w.byGroup {
		gids = append(gids, gid)
	}
	sort.Strings(gids)
	for _, gid := range gids {
		h := w.byGroup[gid]
		out = append(out, wakeEvent{
			Type:    "group.mentioned",
			GroupID: h.GroupID,
			EntryID: h.EntryID,
			From:    h.From,
		})
	}
	if w.mailbox != nil {
		out = append(out, wakeEvent{Type: "mailbox.received", Count: w.mailbox.Count})
	}
	if w.invites != nil {
		out = append(out, wakeEvent{Type: "chat.invites", Count: w.invites.Count, Peers: w.invites.Peers})
	}
	capN := s.eventsCap
	if capN <= 0 {
		capN = wakeEventsCap
	}
	if len(out) > capN {
		out = out[:capN]
	}
	if out == nil {
		return []wakeEvent{}
	}
	return out
}

func deliveredFromWindow(w *wakeWindow) wakeDelivered {
	d := wakeDelivered{
		Peers:  make(map[string]uint64),
		Groups: make(map[string]string),
	}
	if w == nil {
		return d
	}
	for peer, h := range w.byPeer {
		d.Peers[peer] = h.Seq
	}
	for gid, h := range w.byGroup {
		d.Groups[gid] = h.EntryID
	}
	if w.mailbox != nil {
		d.HasMailbox = true
		d.Mailbox = w.mailbox.Count
	}
	if w.invites != nil {
		d.HasInvites = true
		d.Invites = normalizeInvites(w.invites.Peers)
	}
	return d
}

func (b wakeDelivered) exceeds(prev wakeDelivered) bool {
	for peer, seq := range b.Peers {
		old, ok := prev.Peers[peer]
		if !ok || seq > old {
			return true
		}
	}
	for gid, entry := range b.Groups {
		if prev.Groups[gid] != entry {
			return true
		}
	}
	if b.HasMailbox {
		return true
	}
	if b.HasInvites {
		if !prev.HasInvites {
			return true
		}
		seen := make(map[string]struct{}, len(prev.Invites))
		for _, p := range prev.Invites {
			seen[p] = struct{}{}
		}
		for _, p := range b.Invites {
			if _, ok := seen[p]; !ok {
				return true
			}
		}
	}
	return false
}

func mergeDelivered(prev, batch wakeDelivered) wakeDelivered {
	if prev.Peers == nil {
		prev.Peers = make(map[string]uint64)
	}
	if prev.Groups == nil {
		prev.Groups = make(map[string]string)
	}
	for peer, seq := range batch.Peers {
		if seq >= prev.Peers[peer] {
			prev.Peers[peer] = seq
		}
	}
	for gid, entry := range batch.Groups {
		prev.Groups[gid] = entry
	}
	if batch.HasMailbox {
		prev.HasMailbox = true
		if batch.Mailbox > prev.Mailbox {
			prev.Mailbox = batch.Mailbox
		}
	}
	if batch.HasInvites {
		prev.HasInvites = true
		prev.Invites = append([]string(nil), batch.Invites...)
	}
	return prev
}

func normalizeInvites(peers []string) []string {
	seen := make(map[string]struct{}, len(peers))
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func cloneWakeWindow(w *wakeWindow) *wakeWindow {
	if w == nil {
		return nil
	}
	n := &wakeWindow{
		byPeer:  make(map[string]wakePeerHit, len(w.byPeer)),
		byGroup: make(map[string]wakeGroupHit, len(w.byGroup)),
	}
	for k, v := range w.byPeer {
		n.byPeer[k] = v
	}
	for k, v := range w.byGroup {
		n.byGroup[k] = v
	}
	if w.mailbox != nil {
		m := *w.mailbox
		n.mailbox = &m
	}
	if w.invites != nil {
		inv := *w.invites
		inv.Peers = append([]string(nil), w.invites.Peers...)
		n.invites = &inv
	}
	return n
}

func absorbWakeWindow(dst, src *wakeWindow) *wakeWindow {
	if src == nil {
		return dst
	}
	if dst == nil {
		return cloneWakeWindow(src)
	}
	for _, h := range src.byPeer {
		mergeWakeEvent(dst, Event{Type: "chat.received", Data: map[string]any{"peer": h.Peer, "seq": h.Seq}})
	}
	for _, h := range src.byGroup {
		mergeWakeEvent(dst, Event{Type: "group.mentioned", Data: map[string]any{
			"group_id": h.GroupID, "entry_id": h.EntryID, "from": h.From,
		}})
	}
	if src.mailbox != nil {
		mergeWakeEvent(dst, Event{Type: "mailbox.received", Data: map[string]any{"count": src.mailbox.Count}})
	}
	if src.invites != nil {
		mergeWakeEvent(dst, Event{Type: "chat.invites", Data: map[string]any{
			"count": src.invites.Count, "peers": src.invites.Peers,
		}})
	}
	return dst
}

func (s *wakeScheduler) commitDelivered(aid a2al.Address) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if batch, ok := s.outgoing[aid]; ok {
		s.delivered[aid] = mergeDelivered(s.delivered[aid], batch)
		delete(s.outgoing, aid)
	}
	s.mu.Unlock()
	_ = s.saveToDisk()
}

func (s *wakeScheduler) setLast(aid a2al.Address, res wakeLastResult) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.last[aid] = res
	s.mu.Unlock()
	_ = s.saveToDisk()
}

func (s *wakeScheduler) patchLast(aid a2al.Address, fn func(*wakeLastResult)) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	res := s.last[aid]
	fn(&res)
	s.last[aid] = res
	s.mu.Unlock()
}

func (s *wakeScheduler) snapshot(aid a2al.Address) (wakeBinding, wakeLastResult, bool) {
	if s == nil {
		return wakeBinding{}, wakeLastResult{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[aid]
	return b, s.last[aid], ok
}

func (s *wakeScheduler) snapshotHandle(aid a2al.Address) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handles[aid]
}

func (s *wakeScheduler) setHandle(aid a2al.Address, handle string) {
	if s == nil {
		return
	}
	handle = strings.TrimSpace(handle)
	s.mu.Lock()
	if handle == "" {
		delete(s.handles, aid)
	} else {
		if s.handles == nil {
			s.handles = make(map[a2al.Address]string)
		}
		s.handles[aid] = handle
	}
	s.mu.Unlock()
	_ = s.saveToDisk()
}

func argsNeedHandle(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, wakeHandleToken) {
			return true
		}
	}
	return false
}

func expandWakeArgs(args []string, handle string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, wakeHandleToken, handle)
	}
	return out
}

func effectiveWakeCap(bindCap, configCap int64, remaining *int64, remainingUnit string) int64 {
	capn := bindCap
	if capn <= 0 {
		capn = configCap
	}
	if remaining != nil && remainingUnit == wakeCostUnitTokens && *remaining < capn {
		capn = *remaining
	}
	return capn
}

func mapString(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func mapUint64(m map[string]any, k string) uint64 {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case uint64:
		return v
	case uint:
		return uint64(v)
	case int:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case float64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case json.Number:
		n, _ := v.Int64()
		if n < 0 {
			return 0
		}
		return uint64(n)
	default:
		return 0
	}
}
