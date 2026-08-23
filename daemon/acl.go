// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

func (d *Daemon) decideAccess(local, remote a2al.Address, secret string, src net.Addr) bool {
	if local == d.nodeAddr {
		return d.decideNodeAdminAccess(remote, secret, src)
	}
	d.regMu.RLock()
	e := d.reg.Get(local)
	d.regMu.RUnlock()
	if e == nil {
		return true
	}
	if d.aclIP.locked(src) {
		return false
	}
	if !e.ACL.Allows(remote, secret) {
		d.aclIP.noteFail(src)
		return false
	}
	d.aclIP.noteOK(src)
	if usedJoinPassword(e.ACL, remote, secret) {
		d.recordJoinAID(local, remote)
	}
	return true
}

func (d *Daemon) decideNodeAdminAccess(remote a2al.Address, secret string, src net.Addr) bool {
	if d.ra == nil {
		return true
	}
	ok, joinRevoked := d.ra.decide(remote, secret, src)
	if joinRevoked && d.log != nil {
		d.log.Warn("remote admin join password revoked: too many wrong passwords")
	}
	return ok
}

func usedJoinPassword(p *registry.ACLPolicy, remote a2al.Address, secret string) bool {
	if p == nil || secret == "" {
		return false
	}
	for _, e := range p.Allow {
		if e.AID != "" && strings.EqualFold(e.AID, remote.String()) {
			return false
		}
	}
	for _, e := range p.Allow {
		if e.AID == "" && e.Secret == secret {
			return true
		}
	}
	return false
}

func (d *Daemon) recordJoinAID(local, remote a2al.Address) {
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(local)
	if e == nil || e.ACL == nil {
		return
	}
	aidStr := remote.String()
	for _, ent := range e.ACL.Allow {
		if strings.EqualFold(ent.AID, aidStr) {
			return
		}
	}
	next := cloneACL(e.ACL)
	next.Allow = append(next.Allow, registry.ACLEntry{ID: newACLEntryID(), AID: aidStr})
	if err := next.Validate(); err != nil {
		return
	}
	e.ACL = next
	_ = d.reg.Put(e)
}

func redactACL(p *registry.ACLPolicy) map[string]any {
	out := map[string]any{
		"default": "public",
		"paid":    false,
		"deny":    []map[string]any{},
		"allow":   []map[string]any{},
	}
	if p == nil {
		return out
	}
	if p.Default == registry.ACLDefaultDeny {
		out["default"] = "deny"
	}
	out["paid"] = p.Paid
	out["deny"] = redactACLEntries(p.Deny, false)
	out["allow"] = redactACLEntries(p.Allow, false)
	return out
}

func aclForEditor(p *registry.ACLPolicy) map[string]any {
	out := redactACL(p)
	if p == nil {
		return out
	}
	out["deny"] = redactACLEntries(p.Deny, true)
	out["allow"] = redactACLEntries(p.Allow, true)
	return out
}

func redactACLEntries(in []registry.ACLEntry, revealJoin bool) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, e := range in {
		m := map[string]any{"id": e.ID}
		if e.AID != "" {
			m["aid"] = e.AID
		}
		if e.Secret != "" {
			m["secret_set"] = true
			if revealJoin && e.AID == "" {
				m["secret"] = e.Secret
			}
		}
		if e.ExpiresAt != 0 {
			m["expires_at"] = e.ExpiresAt
		}
		if e.MaxUses != 0 {
			m["max_uses"] = e.MaxUses
		}
		if e.BindOnUse {
			m["bind_on_use"] = true
		}
		out = append(out, m)
	}
	return out
}

func newACLEntryID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (d *Daemon) execACLGet(aidStr string) (map[string]any, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return nil, errBadAID
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return nil, errNotFound
	}
	return aclForEditor(e.ACL), nil
}

type aclPatchReq struct {
	Default string `json:"default"`
	Paid    *bool  `json:"paid,omitempty"`
}

func cloneACL(p *registry.ACLPolicy) *registry.ACLPolicy {
	next := &registry.ACLPolicy{Default: registry.ACLDefaultPublic}
	if p == nil {
		return next
	}
	next.Default = p.Default
	next.Paid = p.Paid
	next.Deny = append([]registry.ACLEntry(nil), p.Deny...)
	next.Allow = append([]registry.ACLEntry(nil), p.Allow...)
	return next
}

func (d *Daemon) execACLPatch(aidStr string, req aclPatchReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(aid)
	if e == nil {
		return errNotFound
	}
	next := cloneACL(e.ACL)
	if req.Default != "" {
		next.Default = registry.ACLDefault(req.Default)
	}
	if req.Paid != nil {
		next.Paid = *req.Paid
	}
	if err := next.Validate(); err != nil {
		return err
	}
	e.ACL = next
	return d.reg.Put(e)
}

type aclEntryReq struct {
	AID    string `json:"aid"`
	Secret string `json:"secret,omitempty"`
}

func (d *Daemon) execACLAdd(aidStr, list string, req aclEntryReq) (registry.ACLEntry, error) {
	var zero registry.ACLEntry
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return zero, errBadAID
	}
	ent := registry.ACLEntry{ID: newACLEntryID(), AID: req.AID}
	if list == "allow" && req.AID == "" {
		ent.Secret = req.Secret
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(aid)
	if e == nil {
		return zero, errNotFound
	}
	next := cloneACL(e.ACL)
	if list == "allow" && ent.AID == "" {
		kept := make([]registry.ACLEntry, 0, len(next.Allow))
		for _, old := range next.Allow {
			if old.AID != "" {
				kept = append(kept, old)
			}
		}
		next.Allow = kept
	}
	if list == "deny" {
		next.Deny = append(next.Deny, ent)
	} else {
		next.Allow = append(next.Allow, ent)
	}
	if err := next.Validate(); err != nil {
		return zero, err
	}
	e.ACL = next
	if err := d.reg.Put(e); err != nil {
		return zero, err
	}
	return ent, nil
}

func (d *Daemon) execACLDelete(aidStr, list, id string) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	if id == "" {
		return errNotFound
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(aid)
	if e == nil || e.ACL == nil {
		return errNotFound
	}
	next := cloneACL(e.ACL)
	var found bool
	if list == "deny" {
		next.Deny, found = filterACLEntry(e.ACL.Deny, id)
	} else {
		next.Allow, found = filterACLEntry(e.ACL.Allow, id)
	}
	if !found {
		return errNotFound
	}
	e.ACL = next
	return d.reg.Put(e)
}

func filterACLEntry(src []registry.ACLEntry, id string) ([]registry.ACLEntry, bool) {
	out := make([]registry.ACLEntry, 0, len(src))
	found := false
	for _, ent := range src {
		if ent.ID == id {
			found = true
			continue
		}
		out = append(out, ent)
	}
	return out, found
}

func writeACLError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBadAID):
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad aid"})
	case errors.Is(err, errNotFound):
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, registry.ErrBadACLDefault), errors.Is(err, registry.ErrDenyNeedsAID), errors.Is(err, registry.ErrBadACLAID),
		errors.Is(err, registry.ErrJoinNeedsSecret), errors.Is(err, registry.ErrNamedNoSecret),
		errors.Is(err, registry.ErrDupJoinPassword), errors.Is(err, registry.ErrDupACLAID),
		errors.Is(err, registry.ErrACLBothLists):
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "acl failed"})
	}
}

func (d *Daemon) handleACLGet(w http.ResponseWriter, r *http.Request) {
	out, err := d.execACLGet(r.PathValue("aid"))
	if err != nil {
		writeACLError(w, err)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleACLPatch(w http.ResponseWriter, r *http.Request) {
	var req aclPatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := d.execACLPatch(r.PathValue("aid"), req); err != nil {
		writeACLError(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "updated"})
}

func (d *Daemon) handleACLAllowPost(w http.ResponseWriter, r *http.Request) {
	d.handleACLListPost(w, r, "allow")
}

func (d *Daemon) handleACLDenyPost(w http.ResponseWriter, r *http.Request) {
	d.handleACLListPost(w, r, "deny")
}

func (d *Daemon) handleACLListPost(w http.ResponseWriter, r *http.Request, list string) {
	var req aclEntryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	ent, err := d.execACLAdd(r.PathValue("aid"), list, req)
	if err != nil {
		writeACLError(w, err)
		return
	}
	created := map[string]string{"id": ent.ID}
	if ent.AID != "" {
		created["aid"] = ent.AID
	}
	if ent.Secret != "" {
		created["secret"] = ent.Secret
	}
	writeJSONStatus(w, http.StatusCreated, created)
}

func (d *Daemon) handleACLAllowDelete(w http.ResponseWriter, r *http.Request) {
	d.handleACLListDelete(w, r, "allow")
}

func (d *Daemon) handleACLDenyDelete(w http.ResponseWriter, r *http.Request) {
	d.handleACLListDelete(w, r, "deny")
}

func (d *Daemon) handleACLListDelete(w http.ResponseWriter, r *http.Request, list string) {
	if err := d.execACLDelete(r.PathValue("aid"), list, r.PathValue("id")); err != nil {
		writeACLError(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "deleted"})
}

func rejectAccessStream(str quic.Stream) {
	code := quic.StreamErrorCode(protocol.StreamErrAccessDenied)
	str.CancelWrite(code)
	str.CancelRead(code)
}

func isAccessDeniedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, protocol.ErrAccessDenied) {
		return true
	}
	var se *quic.StreamError
	return errors.As(err, &se) && uint64(se.ErrorCode) == protocol.StreamErrAccessDenied
}
