// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerGroupMCPTools adds all group_* MCP tools to s.
// Called from buildMCPServer.
func (d *Daemon) registerGroupMCPTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_create",
		Description: `Create a Group: a private, append-only log shared by a fixed set of AIDs. Returns group_id and a join link.
You are its only member afterwards. To add others, call group_invite for an AID you already know, or hand out the link from group_get_link.`,
	}, d.mcpGroupCreate)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_list",
		Description: `List the Groups this agent has a local replica of, with entry_count, unread_count and last activity.
Local state only — no network IO. A Group someone invited you to is absent until you call group_join, so an empty list does not mean nobody invited you; check your mailbox with a2al_mailbox_list.`,
	}, d.mcpGroupList)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_invite",
		Description: `Authorise an AID to join a Group. Requires creator or admin role. Writes a signed invite entry and sends the target a mailbox note with the join link, plus as many other member AIDs as that note can carry.
This does not put the Group on their machine: they must call group_join after seeing the note (a2al_mailbox_list) and taking it (a2al_mailbox_poll). group_members lists them as soon as you invite — that is the authorisation in your log, not proof they have a replica. replica_head is absent until you have actually synced with them.`,
	}, d.mcpGroupInvite)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_append",
		Description: `Append a signed entry to a Group. kind defaults to "msg"; the set is open, so any application-defined kind is valid.
body is base64 and capped at 2 KiB decoded — for anything larger call group_object_put first and pass the returned id as ref.
Success means the entry is committed to your local log. It is not a notification: peers pull it on their own schedule, and the group.appended event reports your own write, not theirs.`,
	}, d.mcpGroupAppend)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_read",
		Description: `Read entries from a Group's local replica, at most limit (default 50) in causal order.
after_seq is the start point, exclusive: you get entries with seq > after_seq. It is not remembered between calls, so omitting it means 0 and you get the OLDEST entries of the log, never the newest. To page forward, pass scanned_to_seq from the previous reply — not the seq of the last entry you got: a filtered read examines far past its last match, and only scanned_to_seq says how far, so using anything else makes every call re-walk the same tail.
Reading does not move your read cursor. How fast that advances is yours to decide and is what governs how often you are told about new entries, so call group_mark_read once you have dealt with what you read.
read_cursor and unread_count are reported here so you can see whether you still owe a group_mark_read without a separate group_head call.`,
	}, d.mcpGroupRead)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_head",
		Description: `Return a Group replica's frontier and counters: heads, entry_count, max_seq, read_cursor, unread_count, wanted_count.
wanted_count > 0 means entries are still missing and sync is incomplete. Several heads with wanted_count 0 is ordinary concurrent writing, not damage — no need to repair it.`,
	}, d.mcpGroupHead)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "group_sync",
		Description: `Diagnostics only — the conventional path does not need this. Forces one QUIC sync round with one peer AID.`,
	}, d.mcpGroupSync)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_join",
		Description: `Join a Group and create its local replica. Pass link (from group_get_link or an invite note); otherwise pass group_id and creator_aid. Pass inviter_aid set to the mailbox sender so they can be told if this pull does not complete. Pass member_hints from the invite note when present.
If nobody answers, the replica is still created — you accepted. sync_error with entry_count 0 means nothing pulled yet, not that you were refused. group_sync will not wait them out.`,
	}, d.mcpGroupJoin)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "group_members",
		Description: "Return the current membership list of a Group with each member's role (creator/admin/member/pending/revoked). Each member also carries replica_head/replica_seen_at: how many entries that member held when this node last aligned with it. That is an observation of propagation, not a delivery receipt; it is absent for members never synced with.",
	}, d.mcpGroupMembers)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_mark_read",
		Description: `Advance the read cursor for a Group replica to seq. Unread count = entries past the cursor that this AID did not write itself; your own appends never count as unread.
Nothing else moves this cursor — group_read deliberately does not, so that reading and acknowledging stay separable.
The cursor drives edge-triggered group.unread events: they fire once when unread goes 0→>0 and stay silent until you bring it back to 0. That makes the advance rate your only notification knob: keep it at the head and every entry lights a fresh red dot; let it lag and you are told once; never advance it and you are never interrupted.
seq=0 resets the cursor to "nothing read". Idempotent when seq ≤ current cursor.`,
	}, d.mcpGroupMarkRead)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_object_put",
		Description: `Register a file as a content-addressed object for this AID. Returns object_id to use as group_append ref.

Two modes (mutually exclusive):
- path: absolute path visible to a2ald (must be under files_root if that is set). File is hashed in place; not copied. No size limit.
- body_base64: raw file bytes, base64-encoded. a2ald writes them into files_root/{sha256}.bin. Requires files_root. Use when the file is not directly accessible to a2ald (e.g. container/VM boundary). Supply name with the original filename for display.

body_base64 travels inside this JSON call and so is capped by the API request limit (1 MiB of base64 ≈ 768 KiB of file). For anything larger, stream the bytes instead:

    POST http://127.0.0.1:2121/agents/{aid}/cas?name={filename}
    Content-Type: application/octet-stream
    <raw file bytes>

That endpoint has no size limit, returns the same {object_id, size, name, url}, and needs the same API token as this one. Read objects back with GET /aid/{holder}/cas/{object_id}, which also streams.`,
	}, d.mcpGroupObjectPut)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_object_locate",
		Description: `Look up an object for this AID without downloading it. status=available (local path), expired (this AID has no file), or pending (a hint_aid URL that has not been probed).
pending is not a promise: it means "nobody has checked", so treat it as unknown rather than reachable, and call group_object_get when you actually need the bytes.`,
	}, d.mcpGroupObjectLocate)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "group_object_get",
		Description: `Get an object. Local bytes are returned when already mapped. Otherwise a2ald fetches using the stored grant and hint (or the entry author / a recently aligned member). dest is optional: omitted writes into the object sandbox and maps it. force=true skips the local hit. register=true maps dest on this AID after a successful write to dest.`,
	}, d.mcpGroupObjectGet)
	mcp.AddTool(s, &mcp.Tool{
		Name: "group_get_link",
		Description: `Return the a2al:// join link for a Group. Use it when you need others in this Group and do not have every AID, or when several people should join without collecting addresses. To reach someone, their AID is enough — a link is not required.
The link is a locator, not a credential: holding it grants nothing, and membership is bound to the joining AID. Sharing it is therefore safe, but it also means a recipient you never invited cannot get in with it alone.`,
	}, d.mcpGroupGetLink)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "group_retract",
		Description: "Retract a previously written entry. Writes a signed 'retract' entry referencing the original. The original entry remains in the log for causal integrity but is semantically marked as retracted. Only the original author may retract; enforcement is at the application layer.",
	}, d.mcpGroupRetract)
}

// --- argument structs ---
//
// aid is mandatory on every group_* tool and is never defaulted, even on a
// daemon holding a single identity: it names the authority the call acts as.
// See resolveAgentAID.

type mcpGroupCreateArgs struct {
	AID   string `json:"aid"`
	Title string `json:"title,omitempty"`
}

type mcpGroupListArgs struct {
	AID string `json:"aid"`
}

type mcpGroupInviteArgs struct {
	AID       string `json:"aid"`
	GroupID   string `json:"group_id"`
	TargetAID string `json:"target_aid"`
}

type mcpGroupAppendArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
	// Kind defaults to "msg". The set is open; "msg" is the plain message.
	Kind    string   `json:"kind,omitempty"`
	Body    string   `json:"body,omitempty"`     // base64-encoded, max 2 KiB decoded
	Ref     string   `json:"ref,omitempty"`      // hex object ID (64 chars)
	ReplyTo string   `json:"reply_to,omitempty"` // hex entry ID
	To      []string `json:"to,omitempty"`       // AID strings
}

type mcpGroupReadArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
	// AfterSeq is an exclusive lower bound on local seq: the read returns
	// entries with seq > AfterSeq. It is a start point the caller picks per
	// call and asserts nothing about what the caller has already seen. It is
	// never remembered — the only position this daemon persists is the read
	// cursor, a different thing that moves only when the caller advances it.
	AfterSeq uint64 `json:"after_seq,omitempty"`
	Limit    int    `json:"limit,omitempty"` // default 50
	// Optional filters (all zero-value = no filter).
	Kind    string `json:"kind,omitempty"`
	Author  string `json:"author,omitempty"`   // AID string
	SinceTS int64  `json:"since_ts,omitempty"` // Unix milliseconds
	UntilTS int64  `json:"until_ts,omitempty"` // Unix milliseconds
	To      string `json:"to,omitempty"`       // AID string — entry must mention this AID
	ReplyTo string `json:"reply_to,omitempty"` // hex entry ID
}

type mcpGroupHeadArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
}

type mcpGroupMarkReadArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
	// Seq is the local seq to advance the cursor to. 0 resets to "nothing read".
	Seq uint64 `json:"seq"`
}

type mcpGroupSyncArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
	PeerAID string `json:"peer_aid"`
}

type mcpGroupJoinArgs struct {
	AID        string `json:"aid"`                   // local AID that is joining
	Link       string `json:"link,omitempty"`        // a2al:// invite link (takes priority)
	GroupID    string `json:"group_id,omitempty"`    // hex-encoded group ID (if no link)
	CreatorAID string `json:"creator_aid,omitempty"` // group creator's AID (if no link)
	PeerAID    string `json:"peer_aid,omitempty"`    // sync peer; defaults to creator
	Title      string `json:"title,omitempty"`
	// InviterAID is the mailbox sender of the invite note. Join-progress notes
	// go to this AID, not to whoever happens to be the creator.
	InviterAID string `json:"inviter_aid,omitempty"`
	// member_hints: additional AIDs to try if the primary peer is unreachable.
	// Taken from the invite note when present.
	MemberHints []string `json:"member_hints,omitempty"`
}

type mcpGroupGetLinkArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
}

type mcpGroupRetractArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
	EntryID string `json:"entry_id"` // hex entry ID to retract
}

type mcpGroupMembersArgs struct {
	AID     string `json:"aid"`
	GroupID string `json:"group_id"`
}

type mcpGroupObjectPutArgs struct {
	AID  string `json:"aid"`
	Path string `json:"path,omitempty"`
	// body_base64: raw file bytes, base64-encoded. The daemon writes them into
	// files_root/{sha256}.bin. Requires files_root to be configured. Use when
	// the file is not directly accessible to a2ald (e.g. container/VM boundary).
	Body string `json:"body_base64,omitempty"`
	// name: original filename hint for the body_base64 case; returned as-is in
	// the response so the entry body can carry a human-readable filename.
	Name string `json:"name,omitempty"`
}

type mcpGroupObjectLocateArgs struct {
	AID      string `json:"aid"`
	ObjectID string `json:"object_id"`
	HintAID  string `json:"hint_aid,omitempty"`
}

type mcpGroupObjectGetArgs struct {
	AID         string `json:"aid"`
	ObjectID    string `json:"object_id"`
	Dest        string `json:"dest,omitempty"`
	HintAID     string `json:"hint_aid,omitempty"`
	Register    bool   `json:"register,omitempty"`
	Force       bool   `json:"force,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

// --- handlers ---

func (d *Daemon) mcpGroupCreate(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupCreateArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, priv, err := d.resolveAgent(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	s, err := d.groups.Create(aid, priv, p.Arguments.Title)
	if err != nil {
		return nil, fmt.Errorf("group_create: %w", err)
	}
	gid := s.ID()
	return mcpOK(map[string]any{
		"group_id": hex.EncodeToString(gid[:]),
		"link":     group.GroupURL(aid, gid),
	}), nil
}

func (d *Daemon) mcpGroupList(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupListArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	metas, err := d.groups.List(aid)
	if err != nil {
		return nil, fmt.Errorf("group_list: %w", err)
	}
	items := make([]map[string]any, 0, len(metas))
	for _, m := range metas {
		item := map[string]any{
			"group_id": hex.EncodeToString(m.GroupID[:]),
			"title":    m.Title,
			"creator":  m.CreatorAID.String(),
		}
		// Enrich with live data if the store is already open.
		if s, oerr := d.groups.Open(aid, m.GroupID); oerr == nil {
			item["entry_count"] = s.EntryCount()
			if ts := s.LastEntryTS(); ts != 0 {
				item["last_activity_ms"] = ts
			}
			if ms, merr := s.Members(); merr == nil {
				item["member_count"] = len(ms.All())
			}
		}
		items = append(items, item)
	}
	return mcpOK(map[string]any{"groups": items}), nil
}

func (d *Daemon) mcpGroupInvite(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupInviteArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, priv, err := d.resolveAgent(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	target, err := parseAID(p.Arguments.TargetAID)
	if err != nil {
		return nil, fmt.Errorf("group_invite: bad target_aid: %w", err)
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_invite: %w", err)
	}
	// Verify the caller has admin or creator role before appending an invite entry.
	if ms, merr := s.Members(); merr == nil && !ms.CanInvite(aid) {
		return nil, fmt.Errorf("group_invite: aid %s may not invite: only the creator or an admin can, and this aid is %q; ask a member that group_members reports as creator or admin to invite %s instead",
			aid, roleToString(ms.Role(aid)), p.Arguments.TargetAID)
	}
	e, err := group.NewEntry(priv, aid, s.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(target)),
	)
	if err != nil {
		return nil, fmt.Errorf("group_invite: build entry: %w", err)
	}
	if err := s.Append(e, nil); err != nil {
		return nil, fmt.Errorf("group_invite: append: %w", err)
	}
	d.kickAlignAuthored(aid, groupID)
	d.bus.Publish(Event{Type: "group.appended", AID: aid, Data: map[string]any{
		"group_id": hex.EncodeToString(groupID[:]),
		"entry_id": hex.EncodeToString(e.ID[:]),
	}})

	// Send a Mailbox invitation to the target so they learn about this group.
	go func() {
		if merr := d.sendGroupInviteMail(context.Background(), priv, aid, target, s); merr != nil {
			d.log.Debug("group_invite: mailbox send", "target", target.String(), "err", merr)
		}
	}()
	return mcpOK(map[string]any{"entry_id": hex.EncodeToString(e.ID[:])}), nil
}

func (d *Daemon) mcpGroupAppend(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupAppendArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, priv, err := d.resolveAgent(a.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(a.GroupID)
	if err != nil {
		return nil, err
	}
	if a.Kind == "" {
		a.Kind = "msg"
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_append: %w", err)
	}
	opts := []group.EntryOption{}
	var body []byte
	if a.Body != "" {
		var err error
		body, err = base64.StdEncoding.DecodeString(a.Body)
		if err != nil {
			return nil, fmt.Errorf("group_append: body is not valid base64: %w", err)
		}
		if len(body) > group.MaxEntryBodySize {
			return nil, fmt.Errorf("group_append: body %d bytes exceeds protocol limit of %d bytes; store as object and use ref instead",
				len(body), group.MaxEntryBodySize)
		}
	}
	if a.Ref != "" {
		ref, err := parseHex32(a.Ref)
		if err != nil {
			return nil, fmt.Errorf("group_append: ref: %w", err)
		}
		opts = append(opts, group.WithRef(ref))
		if a.Kind == "file" {
			grant, err := d.ensureShareGrant(aid, ref)
			if err != nil {
				return nil, fmt.Errorf("group_append: grant: %w", err)
			}
			body = mergeJSONGrant(body, grant)
			if len(body) > group.MaxEntryBodySize {
				return nil, fmt.Errorf("group_append: body %d bytes exceeds protocol limit of %d bytes; store as object and use ref instead",
					len(body), group.MaxEntryBodySize)
			}
		}
	}
	if len(body) > 0 {
		opts = append(opts, group.WithBody(body))
	}
	if a.ReplyTo != "" {
		replyTo, err := parseHex32(a.ReplyTo)
		if err != nil {
			return nil, fmt.Errorf("group_append: reply_to: %w", err)
		}
		opts = append(opts, group.WithReplyTo(replyTo))
	}
	for _, aidStr := range a.To {
		t, err := parseAID(aidStr)
		if err != nil {
			return nil, fmt.Errorf("group_append: to[]: bad AID %q: %w", aidStr, err)
		}
		opts = append(opts, group.WithTo(t))
	}
	e, err := group.NewEntry(priv, aid, s.Heads(), a.Kind, opts...)
	if err != nil {
		return nil, fmt.Errorf("group_append: build entry: %w", err)
	}
	if err := s.Append(e, nil); err != nil {
		return nil, fmt.Errorf("group_append: append: %w", err)
	}
	d.kickAlignAuthored(aid, groupID)
	d.bus.Publish(Event{Type: "group.appended", AID: aid, Data: map[string]any{
		"group_id": hex.EncodeToString(groupID[:]),
		"entry_id": hex.EncodeToString(e.ID[:]),
	}})

	return mcpOK(map[string]any{
		"entry_id": hex.EncodeToString(e.ID[:]),
		"seq":      s.MaxSeq(),
	}), nil
}

func (d *Daemon) mcpGroupRead(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupReadArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, err := d.resolveAgentAID(a.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(a.GroupID)
	if err != nil {
		return nil, err
	}

	// Build filter from optional parameters.
	filter := group.ReadFilter{
		Kind:    a.Kind,
		SinceTS: a.SinceTS,
		UntilTS: a.UntilTS,
	}
	if a.Author != "" {
		if filter.Author, err = parseAID(a.Author); err != nil {
			return nil, fmt.Errorf("group_read: author: %w", err)
		}
	}
	if a.To != "" {
		if filter.To, err = parseAID(a.To); err != nil {
			return nil, fmt.Errorf("group_read: to: %w", err)
		}
	}
	if a.ReplyTo != "" {
		if filter.ReplyTo, err = parseHex32(a.ReplyTo); err != nil {
			return nil, fmt.Errorf("group_read: reply_to: %w", err)
		}
	}

	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_read: %w", err)
	}

	// Reading never moves the read cursor. The cursor advance rate is the one
	// knob a consumer holds: a foreground UI keeps it at the head and so sees
	// every entry as a fresh red dot, a busy agent lets it lag and is told
	// once, an auditor never advances it and is never interrupted. Advancing
	// it here would take that knob away and make the third posture
	// inexpressible. See 房间改进计划 §310-318.
	entries, scannedTo, hasMore, err := s.Read(a.AfterSeq, a.Limit, filter)
	if err != nil {
		return nil, fmt.Errorf("group_read: %w", err)
	}
	items := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		items = append(items, entryToMap(e))
	}
	return mcpOK(map[string]any{
		"entries": items,
		// scanned_to_seq states how far this call examined, which is not
		// derivable from the entries returned: a filtered read that reaches the
		// end examined far past its last match. Reporting it is what stops the
		// next call from re-walking that tail.
		"scanned_to_seq": scannedTo,
		"has_more":       hasMore,
		// Reported, not changed: the caller can see whether it still owes a
		// group_mark_read without a separate group_head round-trip.
		"read_cursor":  s.ReadCursor(),
		"unread_count": s.UnreadCount(aid),
	}), nil
}

func (d *Daemon) mcpGroupHead(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupHeadArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_head: %w", err)
	}
	rawHeads := s.Heads()
	heads := make([]string, len(rawHeads))
	for i, h := range rawHeads {
		heads[i] = hex.EncodeToString(h[:])
	}
	// wanted_count: number of parent IDs referenced by local entries but not yet
	// stored locally. >0 means sync is incomplete; 0 with multiple heads means
	// legitimate concurrent writes, not missing data.
	wantedCount := len(s.WantedParents())
	return mcpOK(map[string]any{
		"heads":        heads,
		"entry_count":  s.EntryCount(),
		"max_seq":      s.MaxSeq(),
		"wanted_count": wantedCount,
		"read_cursor":  s.ReadCursor(),
		"unread_count": s.UnreadCount(aid),
	}), nil
}

func (d *Daemon) mcpGroupMarkRead(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupMarkReadArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_mark_read: %w", err)
	}
	advanced, err := s.AdvanceCursor(p.Arguments.Seq)
	if err != nil {
		return nil, fmt.Errorf("group_mark_read: persist cursor: %w", err)
	}
	return mcpOK(map[string]any{
		"advanced":     advanced,
		"read_cursor":  s.ReadCursor(),
		"unread_count": s.UnreadCount(aid),
	}), nil
}

func (d *Daemon) mcpGroupSync(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupSyncArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, _, err := d.resolveAgent(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	peerAID, err := parseAID(p.Arguments.PeerAID)
	if err != nil {
		return nil, fmt.Errorf("group_sync: bad peer_aid: %w", err)
	}
	n, err := d.SyncGroupWith(ctx, groupID, aid, peerAID)
	if err != nil {
		return nil, fmt.Errorf("group_sync: %w", err)
	}
	return mcpOK(map[string]any{"new_entries": n}), nil
}

func (d *Daemon) mcpGroupJoin(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupJoinArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, _, err := d.resolveAgent(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	a := p.Arguments
	var groupID [32]byte
	var creatorAID a2al.Address
	if a.Link != "" {
		// Parse a2al://{creatorAID}/groups/{groupID} invite link.
		creatorAID, groupID, err = group.ParseGroupURL(a.Link)
		if err != nil {
			return nil, fmt.Errorf("group_join: bad link: %w", err)
		}
	} else {
		groupID, err = parseGroupID(a.GroupID)
		if err != nil {
			return nil, err
		}
		creatorAID, err = parseAID(a.CreatorAID)
		if err != nil {
			return nil, fmt.Errorf("group_join: bad creator_aid: %w", err)
		}
	}
	// peer_aid defaults to creator when omitted.
	var peerAID a2al.Address
	if a.PeerAID != "" {
		peerAID, err = parseAID(a.PeerAID)
		if err != nil {
			return nil, fmt.Errorf("group_join: bad peer_aid: %w", err)
		}
	} else {
		peerAID = creatorAID
	}

	if _, err := d.groups.Join(aid, groupID, creatorAID, p.Arguments.Title); err != nil {
		return nil, fmt.Errorf("group_join: init store: %w", err)
	}
	d.clearUnknownGroupLog(aid, groupID)

	inviter := creatorAID
	if a.InviterAID != "" {
		if ia, ierr := parseAID(a.InviterAID); ierr != nil {
			return nil, fmt.Errorf("group_join: bad inviter_aid: %w", ierr)
		} else {
			inviter = ia
		}
	}

	// Initial pull from the primary peer, then invite-note hints.
	// Failing to sync is not fatal: accepting is this call; pulling is separate.
	n, syncErr := d.SyncGroupWith(ctx, groupID, aid, peerAID)
	peers := []a2al.Address{peerAID, creatorAID}
	if syncErr != nil {
		for _, h := range a.MemberHints {
			hintAID, perr := parseAID(h)
			if perr != nil || hintAID == aid || hintAID == peerAID {
				continue
			}
			peers = append(peers, hintAID)
			if n2, herr := d.SyncGroupWith(ctx, groupID, aid, hintAID); herr == nil {
				n += n2
				syncErr = nil
				break
			}
		}
	}

	isMember := false
	entryCount := 0
	maxSeq := uint64(0)
	if s, oerr := d.groups.Open(aid, groupID); oerr == nil {
		if ms, merr := s.Members(); merr == nil {
			isMember = ms.CanWrite(aid)
		}
		entryCount = s.EntryCount()
		maxSeq = s.MaxSeq()
	}
	if entryCount > 0 {
		d.stopJoinProbe(aid, groupID)
		d.kickAlignAID(aid)
	} else {
		d.startJoinProbe(aid, groupID, inviter, peers, syncErr)
	}

	out := map[string]any{
		"group_id":       hex.EncodeToString(groupID[:]),
		"synced_entries": n,
		"entry_count":    entryCount,
		"max_seq":        maxSeq,
		"is_member":      isMember,
	}
	if syncErr != nil {
		out["sync_error"] = syncErr.Error()
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpGroupGetLink(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupGetLinkArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_get_link: %w", err)
	}
	m := s.Meta()
	return mcpOK(map[string]any{
		"link": group.GroupURL(m.CreatorAID, groupID),
	}), nil
}

func (d *Daemon) mcpGroupRetract(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupRetractArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, priv, err := d.resolveAgent(a.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(a.GroupID)
	if err != nil {
		return nil, err
	}
	targetID, err := parseHex32(a.EntryID)
	if err != nil {
		return nil, fmt.Errorf("group_retract: bad entry_id: %w", err)
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_retract: %w", err)
	}
	e, err := group.NewEntry(priv, aid, s.Heads(), group.KindRetract,
		group.WithReplyTo(targetID),
	)
	if err != nil {
		return nil, fmt.Errorf("group_retract: build entry: %w", err)
	}
	if err := s.Append(e, nil); err != nil {
		return nil, fmt.Errorf("group_retract: append: %w", err)
	}
	d.kickAlignAuthored(aid, groupID)
	d.bus.Publish(Event{Type: "group.appended", AID: aid, Data: map[string]any{
		"group_id": hex.EncodeToString(groupID[:]),
		"entry_id": hex.EncodeToString(e.ID[:]),
	}})
	return mcpOK(map[string]any{
		"retract_entry_id": hex.EncodeToString(e.ID[:]),
	}), nil
}

func (d *Daemon) mcpGroupMembers(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupMembersArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(p.Arguments.GroupID)
	if err != nil {
		return nil, err
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, fmt.Errorf("group_members: %w", err)
	}
	ms, err := s.Members()
	if err != nil {
		return nil, fmt.Errorf("group_members: %w", err)
	}
	all := ms.All()
	members := make([]map[string]any, 0, len(all))
	for m, role := range all {
		entry := map[string]any{
			"aid":  m.String(),
			"role": roleToString(role),
		}
		if m != aid {
			// What we last observed of that replica, not a delivery receipt:
			// a writer can see how far its entries have spread instead of
			// assuming a center delivered them. Absent means never synced.
			if head, at, ok := d.replicaHead(aid, m, groupID); ok {
				entry["replica_head"] = head
				entry["replica_seen_at"] = at.UTC().Format(time.RFC3339)
			}
		}
		members = append(members, entry)
	}
	return mcpOK(map[string]any{
		"local_head": s.EntryCount(),
		"members":    members,
	}), nil
}

// roleToString converts a MemberRole to a human-readable string.
func roleToString(r group.MemberRole) string {
	switch r {
	case group.RoleCreator:
		return "creator"
	case group.RoleAdmin:
		return "admin"
	case group.RoleMember:
		return "member"
	case group.RolePending:
		return "pending"
	case group.RoleRevoked:
		return "revoked"
	default:
		return "none"
	}
}

// --- helpers shared across group_mcp.go ---

// resolveAgentAID resolves the acting local AID for a group_* call.
//
// aid is deliberately mandatory and is never inferred, not even when this
// daemon holds exactly one identity. An AID is an authority, not a
// convenience parameter: every call must name the identity it acts as, so
// that access control has something to bind to. For the same reason the
// error must not enumerate the identities held here — that would hand an
// unauthorised caller the list it is not entitled to.
func (d *Daemon) resolveAgentAID(aidStr string) (a2al.Address, error) {
	if aidStr == "" {
		return a2al.Address{}, errors.New("aid is required: name the local identity this call acts as; a2al_agents_list returns the identities registered here")
	}
	aid, err := parseAID(aidStr)
	if err != nil {
		return a2al.Address{}, err
	}
	// Registered local identities count as present; unregistered addresses are a no-op.
	d.noteActingAgent(aid)
	return aid, nil
}

// resolveAgent is resolveAgentAID plus the operational private key, for calls
// that sign an entry.
func (d *Daemon) resolveAgent(aidStr string) (a2al.Address, ed25519.PrivateKey, error) {
	aid, err := d.resolveAgentAID(aidStr)
	if err != nil {
		return a2al.Address{}, nil, err
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return a2al.Address{}, nil, fmt.Errorf("aid %s is not registered with this daemon, so there is no key to sign with: a2al_agents_list shows the identities registered here, and a2al_agent_register adds this one if you hold its key", aid)
	}
	return aid, ed25519.PrivateKey(e.OpPriv), nil
}

// parseAID parses an AID string.
func parseAID(s string) (a2al.Address, error) {
	aid, err := a2al.ParseAddress(s)
	if err != nil {
		return a2al.Address{}, fmt.Errorf("bad AID %q: %w", s, err)
	}
	return aid, nil
}

// parseGroupID decodes a 64-hex-char group ID.
func parseGroupID(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		if s == "" {
			return [32]byte{}, errors.New("group_id is required: group_list shows the group_id of every group this aid has joined, and group_create returns one; if you only have an a2al:// link, pass it to group_join as link instead of splitting it up")
		}
		return [32]byte{}, fmt.Errorf("group_id must be 64 hex characters, got %d (%q); take it verbatim from group_list, group_create or group_head, not from an a2al:// link — pass links to group_join as link",
			len(s), s)
	}
	var id [32]byte
	copy(id[:], b)
	return id, nil
}

// parseHex32 decodes a 64-hex-char value into [32]byte.
func parseHex32(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("expected 64-char hex, got %d chars", len(s))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// mcpOK wraps a result map in the MCP success envelope.
func mcpOK(m map[string]any) *mcp.CallToolResultFor[map[string]any] {
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}
}

// entryToMap converts an EntryRead to a JSON-friendly map for MCP responses.
//
// Field encoding rules (applied consistently to all binary identifiers):
//   - [32]byte IDs → lowercase hex string (64 chars)
//   - a2al.Address → canonical AID text via .String()
//   - timestamps → Unix milliseconds int64 (consistent with entry.ts)
//
// The Seq field (local arrival order, 1-based) is included so callers can
// correlate display rows back to the Read cursor without counting; this
// mirrors the Kafka "offset" convention for append-only logs.
//
// Membership entry bodies (invite/revoke/grant_admin/revoke_admin/propose_invite)
// are decoded from CBOR to a readable {"target_aid": "..."} struct rather than
// raw base64, since their schema is part of the protocol definition.
func entryToMap(er group.EntryRead) map[string]any {
	e := er.Entry
	m := map[string]any{
		"seq":    er.Seq,
		"id":     hex.EncodeToString(e.ID[:]),
		"author": e.Author.String(),
		"kind":   e.Kind,
		"ts":     e.TS,
	}
	if len(e.Parents) > 0 {
		ps := make([]string, len(e.Parents))
		for i, p := range e.Parents {
			ps[i] = hex.EncodeToString(p[:])
		}
		m["parents"] = ps
	}
	if e.ReplyTo != ([32]byte{}) {
		m["reply_to"] = hex.EncodeToString(e.ReplyTo[:])
	}
	if len(e.To) > 0 {
		tos := make([]string, len(e.To))
		for i, a := range e.To {
			tos[i] = a.String()
		}
		m["to"] = tos
	}
	if len(e.Body) > 0 {
		switch e.Kind {
		case group.KindInvite, group.KindRevoke, group.KindGrantAdmin, group.KindRevokeAdmin, group.KindProposeInvite:
			// Membership entries carry a CBOR-encoded target AID.
			// Decode to a readable struct rather than opaque base64.
			if target, ok := group.DecodeMemberBody(e.Body); ok {
				m["body"] = map[string]any{"target_aid": target.String()}
			} else {
				m["body"] = base64.StdEncoding.EncodeToString(e.Body)
			}
		default:
			m["body"] = base64.StdEncoding.EncodeToString(e.Body)
		}
	}
	if e.Ref != ([32]byte{}) {
		m["ref"] = hex.EncodeToString(e.Ref[:])
	}
	return m
}

// --- object store tools ---

func (d *Daemon) mcpGroupObjectPut(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupObjectPutArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, err := d.resolveAgentAID(a.AID)
	if err != nil {
		return nil, err
	}

	var id [32]byte
	var size int64
	var name string

	hasBody := strings.TrimSpace(a.Body) != ""
	hasPath := strings.TrimSpace(a.Path) != ""
	if hasBody && hasPath {
		return nil, errors.New("group_object_put: pass exactly one of path or body_base64, not both")
	}
	if hasBody {
		// body_base64 mode: decode → stream into files_root → register.
		data, err := base64.StdEncoding.DecodeString(a.Body)
		if err != nil {
			return nil, fmt.Errorf("group_object_put: body_base64 is not valid base64: %w", err)
		}
		id, size, name, err = d.writeBodyToFilesRoot(aid, data, a.Name)
		if err != nil {
			return nil, fmt.Errorf("group_object_put: %w", err)
		}
	} else if hasPath {
		// path mode: hash in place.
		id, size, name, err = d.registerLocalObject(aid, a.Path)
		if err != nil {
			return nil, fmt.Errorf("group_object_put: %w", err)
		}
	} else {
		return nil, errors.New("group_object_put: pass exactly one of path or body_base64 — path when a2ald can read the file itself (no size limit), body_base64 when it cannot, e.g. across a container boundary (capped near 768 KiB of file; stream larger ones to POST /agents/{aid}/cas)")
	}

	return mcpOK(map[string]any{
		"object_id": hex.EncodeToString(id[:]),
		"size":      size,
		"name":      name,
		"url":       group.CASURL(aid, id),
	}), nil
}

func (d *Daemon) mcpGroupObjectLocate(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupObjectLocateArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, err := d.resolveAgentAID(a.AID)
	if err != nil {
		return nil, err
	}
	objectID, err := parseHex32(a.ObjectID)
	if err != nil {
		return nil, fmt.Errorf("group_object_locate: object_id: %w", err)
	}
	var hint a2al.Address
	if strings.TrimSpace(a.HintAID) != "" {
		hint, err = parseAID(a.HintAID)
		if err != nil {
			return nil, fmt.Errorf("group_object_locate: hint_aid: %w", err)
		}
	}
	return mcpOK(d.locateObject(aid, objectID, hint)), nil
}

func (d *Daemon) mcpGroupObjectGet(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpGroupObjectGetArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	aid, err := d.resolveAgentAID(a.AID)
	if err != nil {
		return nil, err
	}
	objectID, err := parseHex32(a.ObjectID)
	if err != nil {
		return nil, fmt.Errorf("group_object_get: object_id: %w", err)
	}
	var hint a2al.Address
	if strings.TrimSpace(a.HintAID) != "" {
		hint, err = parseAID(a.HintAID)
		if err != nil {
			return nil, fmt.Errorf("group_object_get: hint_aid: %w", err)
		}
	}
	dest := strings.TrimSpace(a.Dest)
	if dest != "" {
		dest, err = d.absUnderFilesRoot(dest)
		if err != nil {
			return nil, fmt.Errorf("group_object_get: dest: %w", err)
		}
	}

	src, size, err := d.ensureObjectLocal(ctx, aid, objectID, hint, a.Force, false, a.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("group_object_get: %w", err)
	}
	if dest == "" || dest == src {
		return mcpOK(map[string]any{
			"object_id": a.ObjectID,
			"path":      src,
			"size":      size,
		}), nil
	}
	if err := copyFile(src, dest); err != nil {
		return nil, fmt.Errorf("group_object_get: copy: %w", err)
	}
	if a.Register {
		if _, _, _, err := d.registerLocalObject(aid, dest); err != nil {
			return nil, fmt.Errorf("group_object_get: register: %w", err)
		}
	}
	st, err := os.Stat(dest)
	if err != nil {
		return nil, fmt.Errorf("group_object_get: %w", err)
	}
	return mcpOK(map[string]any{
		"object_id": a.ObjectID,
		"path":      dest,
		"size":      st.Size(),
	}), nil
}
