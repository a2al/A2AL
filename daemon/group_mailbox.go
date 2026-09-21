// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/protocol"
)

// inviteNote is the plaintext body of a MailboxMsgGroupInvite note.
//
// It is JSON, not CBOR, because the daemon is not a consumer: the note
// goes straight to the agent, which must be able to read it with nothing but a
// base64 decode. link can be passed to group_join verbatim. member_hints are
// extra AIDs that fit under the 512-byte mailbox payload cap.
//
// The note carries no authority. Membership is the signed invite entry in the
// log; group_join enacts it.
type inviteNote struct {
	Link        string   `json:"link"`
	Title       string   `json:"title,omitempty"`
	MemberHints []string `json:"member_hints,omitempty"`
}

// inviteNoteMaxTitle bounds the title so a long room name cannot push the
// encrypted payload past the mailbox cap before any hints are added.
const inviteNoteMaxTitle = 80

// joinNotice is JSON in an ordinary mailbox text note (MailboxMsgText), sent
// from the joining AID to the inviter. kind distinguishes it from chat.
// The daemon does not consume it.
type joinNotice struct {
	Kind   string `json:"kind"`
	Link   string `json:"link,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

const (
	joinNoticeDeferred  = "deferred"
	joinNoticeGaveUp    = "gave_up"
	joinNoticeReasonCap = 160
)

// sendGroupInviteMail delivers an invite note to toAID, packed to the mailbox
// payload cap. The daemon does not act on this note at either end.
func (d *Daemon) sendGroupInviteMail(ctx context.Context, _ ed25519.PrivateKey, fromAID, toAID a2al.Address, s *group.Store) error {
	meta := s.Meta()
	title := meta.Title
	if len(title) > inviteNoteMaxTitle {
		title = title[:inviteNoteMaxTitle]
	}
	link := group.GroupURL(meta.CreatorAID, s.ID())
	hints := inviteHintCandidates(s, toAID)

	body, err := json.Marshal(inviteNote{Link: link, Title: title})
	if err != nil {
		return err
	}
	if pub, _, kerr := ed25519.GenerateKey(rand.Reader); kerr == nil {
		body, _ = packInviteNote(fromAID, toAID, pub, link, title, hints)
	}

	_, err = d.execMailboxSend(ctx, fromAID.String(), toAID.String(), protocol.MailboxMsgGroupInvite, body)
	return err
}

func inviteHintCandidates(s *group.Store, exclude a2al.Address) []string {
	ms, err := s.Members()
	if err != nil {
		return nil
	}
	creator := s.Meta().CreatorAID
	var rest []a2al.Address
	for m, role := range ms.All() {
		if m == exclude || role < group.RoleMember {
			continue
		}
		if m == creator {
			continue
		}
		rest = append(rest, m)
	}
	sort.Slice(rest, func(i, j int) bool {
		return bytes.Compare(rest[i][:], rest[j][:]) < 0
	})
	out := make([]string, 0, 1+len(rest))
	if creator != exclude {
		out = append(out, creator.String())
	}
	for _, m := range rest {
		out = append(out, m.String())
	}
	return out
}

// packInviteNote adds member_hints while the encrypted mailbox payload still
// fits in protocol.MaxMailboxPayloadCBOR. Zero hints always attempted first.
func packInviteNote(from, to a2al.Address, toPub ed25519.PublicKey, link, title string, hints []string) ([]byte, []string) {
	used := []string{}
	body := mustInviteJSON(link, title, nil)
	for _, h := range hints {
		trial := append(append([]string{}, used...), h)
		b := mustInviteJSON(link, title, trial)
		if _, err := protocol.EncodeMailboxPayload(from, to, toPub, protocol.MailboxMsgGroupInvite, b); err != nil {
			break
		}
		used = trial
		body = b
	}
	return body, used
}

func mustInviteJSON(link, title string, hints []string) []byte {
	n := inviteNote{Link: link, Title: title}
	if len(hints) > 0 {
		n.MemberHints = hints
	}
	b, err := json.Marshal(n)
	if err != nil {
		return []byte(`{"link":""}`)
	}
	return b
}

func (d *Daemon) sendJoinNotice(ctx context.Context, from, inviter a2al.Address, gid [32]byte, status, reason string) {
	if inviter == (a2al.Address{}) || inviter == from {
		return
	}
	n := joinNotice{Kind: "group_join", Status: status, Reason: clipReason(reason)}
	if d.groups != nil {
		if s, err := d.groups.Open(from, gid); err == nil {
			n.Link = group.GroupURL(s.Meta().CreatorAID, gid)
		}
	}
	body, err := json.Marshal(n)
	if err != nil {
		return
	}
	if pub, _, kerr := ed25519.GenerateKey(rand.Reader); kerr == nil {
		body = fitJoinNotice(from, inviter, pub, n)
	}
	if _, err := d.execMailboxSend(ctx, from.String(), inviter.String(), protocol.MailboxMsgText, body); err != nil && d.log != nil {
		d.log.Debug("group join notice: send", "status", status, "err", err)
	}
}

func fitJoinNotice(from, to a2al.Address, toPub ed25519.PublicKey, n joinNotice) []byte {
	try := func(x joinNotice) []byte {
		b, err := json.Marshal(x)
		if err != nil {
			return nil
		}
		if _, err := protocol.EncodeMailboxPayload(from, to, toPub, protocol.MailboxMsgText, b); err != nil {
			return nil
		}
		return b
	}
	if b := try(n); b != nil {
		return b
	}
	n.Reason = ""
	if b := try(n); b != nil {
		return b
	}
	n.Link = ""
	if b := try(n); b != nil {
		return b
	}
	b, _ := json.Marshal(joinNotice{Kind: "group_join", Status: n.Status})
	return b
}

func clipReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= joinNoticeReasonCap {
		return s
	}
	return s[:joinNoticeReasonCap]
}

// There is deliberately no inbound handler here.
//
// The daemon does not inspect, consume, or act on Group messages found in the
// mailbox. An invite arrives as an ordinary note; the agent decodes it and
// decides whether to call group_join. Joining is the only path that creates a
// local replica. A join notice is likewise left for the inviter's agent.
