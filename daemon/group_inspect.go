// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

const inspectEntryLimitCap = 50

// Group inspect HTTP is a read-only projection of a local replica for the
// Web UI. It must not record liveness: looking is not the AID acting.
// Do not wrap these handlers in withAgentMiddleware, and do not call
// resolveAgentAID / noteActingAgent.

func (d *Daemon) handleGroupInspectList(w http.ResponseWriter, r *http.Request) {
	aid, ok := inspectParseAID(w, r.PathValue("aid"))
	if !ok {
		return
	}
	if d.groups == nil {
		writeJSON(w, map[string]any{"groups": []any{}})
		return
	}
	metas, err := d.groups.List(aid)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	items := make([]map[string]any, 0, len(metas))
	for _, m := range metas {
		items = append(items, d.inspectGroupItem(aid, m))
	}
	writeJSON(w, map[string]any{"groups": items})
}

func (d *Daemon) handleGroupInspectHead(w http.ResponseWriter, r *http.Request) {
	_, s, ok := d.inspectOpen(w, r)
	if !ok {
		return
	}
	writeJSON(w, inspectHeadMap(s))
}

func (d *Daemon) handleGroupInspectEntries(w http.ResponseWriter, r *http.Request) {
	_, s, ok := d.inspectOpen(w, r)
	if !ok {
		return
	}
	afterSeq := parseAfterSeq(r.URL.Query().Get("after_seq"))
	limit := inspectEntryLimitCap
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{
				"error": "limit must be a positive integer, at most 50",
			})
			return
		}
		if n < limit {
			limit = n
		}
	}
	entries, scannedTo, hasMore, err := s.Read(afterSeq, limit, group.ReadFilter{})
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	items := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		items = append(items, entryToMap(e))
	}
	writeJSON(w, map[string]any{
		"entries":        items,
		"scanned_to_seq": scannedTo,
		"has_more":       hasMore,
	})
}

func inspectParseAID(w http.ResponseWriter, aidStr string) (a2al.Address, bool) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad aid"})
		return a2al.Address{}, false
	}
	return aid, true
}

func (d *Daemon) inspectOpen(w http.ResponseWriter, r *http.Request) (a2al.Address, *group.Store, bool) {
	aid, ok := inspectParseAID(w, r.PathValue("aid"))
	if !ok {
		return a2al.Address{}, nil, false
	}
	groupID, err := parseGroupID(r.PathValue("group_id"))
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return a2al.Address{}, nil, false
	}
	if d.groups == nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error": "this identity has no local replica of that group",
		})
		return a2al.Address{}, nil, false
	}
	s, err := d.groups.Open(aid, groupID)
	if err != nil {
		if strings.Contains(err.Error(), "no local replica") || errors.Is(err, group.ErrNoStore) {
			writeJSONStatus(w, http.StatusNotFound, map[string]string{
				"error": "this identity has no local replica of that group",
			})
			return a2al.Address{}, nil, false
		}
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return a2al.Address{}, nil, false
	}
	return aid, s, true
}

func (d *Daemon) inspectGroupItem(aid a2al.Address, m group.Meta) map[string]any {
	item := map[string]any{
		"group_id": hex.EncodeToString(m.GroupID[:]),
		"title":    m.Title,
		"creator":  m.CreatorAID.String(),
	}
	if s, err := d.groups.Open(aid, m.GroupID); err == nil {
		item["entry_count"] = s.EntryCount()
		if ts := s.LastEntryTS(); ts != 0 {
			item["last_activity_ms"] = ts
		}
		if ms, merr := s.Members(); merr == nil {
			item["member_count"] = len(ms.All())
		}
	}
	return item
}

func inspectHeadMap(s *group.Store) map[string]any {
	id := s.ID()
	out := map[string]any{
		"group_id":    hex.EncodeToString(id[:]),
		"title":       s.Meta().Title,
		"entry_count": s.EntryCount(),
		"max_seq":     s.MaxSeq(),
	}
	if ms, err := s.Members(); err == nil {
		out["member_count"] = len(ms.All())
	}
	return out
}
