// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

// MemberRole represents the permission level of an AID within a Group.
// Values form a partial order: higher means more authority.
type MemberRole uint8

const (
	RoleNone    MemberRole = 0 // not a member; no record in the log
	RoleRevoked MemberRole = 1 // was a member; access explicitly revoked — distinct from never-joined
	RolePending MemberRole = 2 // proposed via propose_invite; awaiting admin approval
	RoleMember  MemberRole = 3 // active member; may write entries and propose invites
	RoleAdmin   MemberRole = 4 // may directly invite new members and revoke members
	RoleCreator MemberRole = 5 // initial authority; cannot be revoked
)

// MemberSet is the membership state computed by replaying the entry log.
type MemberSet struct {
	members map[a2al.Address]MemberRole
}

// Role returns the current role of aid. Returns RoleNone for unknown AIDs.
func (ms MemberSet) Role(aid a2al.Address) MemberRole {
	if ms.members == nil {
		return RoleNone
	}
	return ms.members[aid]
}

// CanWrite reports whether aid may append entries to the group.
func (ms MemberSet) CanWrite(aid a2al.Address) bool { return ms.Role(aid) >= RoleMember }

// CanInvite reports whether aid may directly invite new members (without approval).
func (ms MemberSet) CanInvite(aid a2al.Address) bool { return ms.Role(aid) >= RoleAdmin }

// CanGrantAdmin reports whether aid may promote members to admin.
func (ms MemberSet) CanGrantAdmin(aid a2al.Address) bool { return ms.Role(aid) == RoleCreator }

// CanSync reports whether aid may open a sync connection to read the entry log.
// Active and pending members may sync; strangers and revoked members may not.
func (ms MemberSet) CanSync(aid a2al.Address) bool { return ms.Role(aid) >= RolePending }

// All returns a copy of the full member map.
func (ms MemberSet) All() map[a2al.Address]MemberRole {
	out := make(map[a2al.Address]MemberRole, len(ms.members))
	for k, v := range ms.members {
		out[k] = v
	}
	return out
}

// memberBody is the CBOR body for membership-related entries
// (invite, revoke, grant_admin, revoke_admin, propose_invite).
type memberBody struct {
	TargetAID []byte `cbor:"1,keyasint"`
}

// EncodeMemberBody returns CBOR body bytes for a membership entry targeting aid.
func EncodeMemberBody(aid a2al.Address) []byte {
	b, _ := cbor.Marshal(memberBody{TargetAID: aid[:]})
	return b
}

// DecodeMemberBody decodes a membership entry body and returns the target AID.
// Returns false if the body is not a valid membership body or the AID length is wrong.
func DecodeMemberBody(body []byte) (a2al.Address, bool) {
	var mb memberBody
	if err := cbor.Unmarshal(body, &mb); err != nil || len(mb.TargetAID) != 21 {
		return a2al.Address{}, false
	}
	var addr a2al.Address
	copy(addr[:], mb.TargetAID)
	return addr, true
}

// Apply updates ms in-place to reflect the membership effect of a single entry.
// creatorAID is required to protect the creator from revocation and to seed
// the initial state when ms is empty. Entry kinds that do not affect membership
// are silently ignored.
func (ms *MemberSet) Apply(e Entry, creatorAID a2al.Address) {
	if ms.members == nil {
		ms.members = make(map[a2al.Address]MemberRole)
		ms.members[creatorAID] = RoleCreator
	}
	authorRole := ms.Role(e.Author)
	switch e.Kind {
	case KindInvite:
		if authorRole >= RoleAdmin {
			if target, ok := decodeMemberTarget(e.Body); ok && ms.Role(target) < RoleMember {
				ms.members[target] = RoleMember
			}
		}
	case KindProposeInvite:
		// Only truly unknown AIDs (never been a member) can be proposed.
		if authorRole >= RoleMember {
			if target, ok := decodeMemberTarget(e.Body); ok && ms.Role(target) == RoleNone {
				ms.members[target] = RolePending
			}
		}
	case KindRevoke:
		target, ok := decodeMemberTarget(e.Body)
		if !ok || target == creatorAID {
			break
		}
		self := e.Author == target && authorRole >= RoleMember
		if self || authorRole >= RoleAdmin {
			ms.members[target] = RoleRevoked // distinct from RoleNone: was a member
		}
	case KindGrantAdmin:
		if authorRole == RoleCreator {
			if target, ok := decodeMemberTarget(e.Body); ok && ms.Role(target) >= RoleMember {
				ms.members[target] = RoleAdmin
			}
		}
	case KindRevokeAdmin:
		if authorRole == RoleCreator {
			if target, ok := decodeMemberTarget(e.Body); ok && ms.Role(target) == RoleAdmin {
				ms.members[target] = RoleMember
			}
		}
	}
}

// replayMembers computes the MemberSet by replaying entries in the given order.
// entries must be in causal order (topological, with TS+ID tiebreak).
// creatorAID is read from Meta and given RoleCreator unconditionally.
func replayMembers(entries []Entry, creatorAID a2al.Address) MemberSet {
	ms := MemberSet{members: make(map[a2al.Address]MemberRole)}
	ms.members[creatorAID] = RoleCreator
	for _, e := range entries {
		ms.Apply(e, creatorAID)
	}
	return ms
}

func decodeMemberTarget(body []byte) (a2al.Address, bool) {
	var mb memberBody
	if err := cbor.Unmarshal(body, &mb); err != nil || len(mb.TargetAID) != 21 {
		return a2al.Address{}, false
	}
	var aid a2al.Address
	copy(aid[:], mb.TargetAID)
	return aid, true
}
