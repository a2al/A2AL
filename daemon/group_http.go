// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/a2al/a2al/group"
)

type groupAppendBody struct {
	Text     string `json:"text"`
	ObjectID string `json:"object_id"`
	Name     string `json:"name"`
}

func (d *Daemon) handleGroupAppend(w http.ResponseWriter, r *http.Request) {
	var body groupAppendBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := d.execGroupAppendHTTP(r.PathValue("aid"), r.PathValue("group_id"), body)
	if err != nil {
		writeGroupAppendErr(w, err)
		return
	}
	writeJSON(w, out)
}

var (
	errGroupLeaveCreator = errors.New("the creator cannot leave the group")
	errGroupLeaveRole    = errors.New("not a member of this group")
)

func (d *Daemon) handleGroupLeave(w http.ResponseWriter, r *http.Request) {
	var dummy map[string]any
	_ = json.NewDecoder(r.Body).Decode(&dummy)
	out, err := d.execGroupLeave(r.PathValue("aid"), r.PathValue("group_id"))
	if err != nil {
		writeGroupAppendErr(w, err)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) execGroupLeave(aidStr, groupIDStr string) (map[string]any, error) {
	aid, priv, err := d.resolveAgent(aidStr)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(groupIDStr)
	if err != nil {
		return nil, err
	}
	if d.groups == nil {
		return nil, group.ErrNoStore
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, err
	}
	ms, err := s.Members()
	if err != nil {
		return nil, err
	}
	switch ms.Role(aid) {
	case group.RoleCreator:
		return nil, errGroupLeaveCreator
	case group.RoleNone, group.RoleRevoked, group.RolePending:
		return nil, errGroupLeaveRole
	}
	e, err := group.NewEntry(priv, aid, s.Heads(), group.KindRevoke,
		group.WithBody(group.EncodeMemberBody(aid)),
	)
	if err != nil {
		return nil, fmt.Errorf("build entry: %w", err)
	}
	if err := s.Append(e, nil); err != nil {
		return nil, fmt.Errorf("append: %w", err)
	}
	d.kickAlignAuthored(aid, groupID)
	d.bus.Publish(Event{Type: "group.appended", AID: aid, Data: map[string]any{
		"group_id": hex.EncodeToString(groupID[:]),
		"entry_id": hex.EncodeToString(e.ID[:]),
	}})
	if err := d.groups.Drop(aid, groupID); err != nil {
		return nil, fmt.Errorf("drop replica: %w", err)
	}
	return map[string]any{"ok": true}, nil
}

func (d *Daemon) execGroupAppendHTTP(aidStr, groupIDStr string, body groupAppendBody) (map[string]any, error) {
	obj := strings.TrimSpace(body.ObjectID)
	hasText := body.Text != ""
	hasObj := obj != ""
	if hasText && hasObj {
		return nil, errors.New("provide exactly one of text or object_id")
	}
	if !hasText && !hasObj {
		return nil, errors.New("provide text or object_id")
	}

	aid, priv, err := d.resolveAgent(aidStr)
	if err != nil {
		return nil, err
	}
	groupID, err := parseGroupID(groupIDStr)
	if err != nil {
		return nil, err
	}
	if d.groups == nil {
		return nil, group.ErrNoStore
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		return nil, err
	}

	kind := "msg"
	var opts []group.EntryOption
	if hasText {
		raw := []byte(body.Text)
		if len(raw) > group.MaxEntryBodySize {
			return nil, fmt.Errorf("body %d bytes exceeds protocol limit of %d bytes", len(raw), group.MaxEntryBodySize)
		}
		opts = append(opts, group.WithBody(raw))
	} else {
		ref, err := parseHex32(obj)
		if err != nil {
			return nil, fmt.Errorf("object_id: %w", err)
		}
		name := stripFileName(body.Name)
		var size int64
		if p, sz, ok := d.lookupLocalObject(aid, ref); ok {
			size = sz
			if name == "" {
				name = stripFileName(p)
			}
		}
		if name == "" {
			name = "file"
		}
		grant, err := d.ensureShareGrant(aid, ref)
		if err != nil {
			return nil, err
		}
		desc, err := json.Marshal(map[string]any{"name": name, "size": size, "grant": grant})
		if err != nil {
			return nil, err
		}
		kind = "file"
		opts = append(opts, group.WithRef(ref), group.WithBody(desc))
	}

	e, err := group.NewEntry(priv, aid, s.Heads(), kind, opts...)
	if err != nil {
		return nil, fmt.Errorf("build entry: %w", err)
	}
	if err := s.Append(e, nil); err != nil {
		return nil, fmt.Errorf("append: %w", err)
	}
	d.kickAlignAuthored(aid, groupID)
	d.bus.Publish(Event{Type: "group.appended", AID: aid, Data: map[string]any{
		"group_id": hex.EncodeToString(groupID[:]),
		"entry_id": hex.EncodeToString(e.ID[:]),
	}})
	return map[string]any{
		"entry_id": hex.EncodeToString(e.ID[:]),
		"seq":      s.MaxSeq(),
	}, nil
}

func stripFileName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\\", "/")
	s = path.Base(s)
	if s == "." || s == "/" || s == "" {
		return ""
	}
	return s
}

func writeGroupAppendErr(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	msg := err.Error()
	switch {
	case errors.Is(err, group.ErrNoStore) || strings.Contains(msg, "no local replica"):
		code = http.StatusNotFound
	case errors.Is(err, errGroupLeaveCreator):
		code = http.StatusConflict
	case errors.Is(err, errGroupLeaveRole):
		code = http.StatusForbidden
	case strings.Contains(msg, "not registered"):
		code = http.StatusNotFound
	case strings.Contains(msg, "build entry") || strings.HasPrefix(msg, "append:") || strings.HasPrefix(msg, "drop replica"):
		code = http.StatusInternalServerError
	}
	writeJSONStatus(w, code, map[string]string{"error": msg})
}
