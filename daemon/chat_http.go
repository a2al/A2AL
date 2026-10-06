// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/chat"
)

func (d *Daemon) handleChatInspectContacts(w http.ResponseWriter, r *http.Request) {
	aid, ok := inspectParseAID(w, r.PathValue("aid"))
	if !ok {
		return
	}
	st, err := d.chatStore(aid)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, d.chatContactsMap(st))
}

func (d *Daemon) handleChatInspectLog(w http.ResponseWriter, r *http.Request) {
	aid, ok := inspectParseAID(w, r.PathValue("aid"))
	if !ok {
		return
	}
	peer, err := a2al.ParseAddress(r.PathValue("peer"))
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad peer"})
		return
	}
	st, err := d.chatStore(aid)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	after := parseAfterSeq(r.URL.Query().Get("after_seq"))
	limit := chat.DefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = n
	}
	entries, scanned, more := st.Read(peer, after, limit)
	items := make([]map[string]any, 0, len(entries))
	for _, rec := range entries {
		items = append(items, d.recToMap(aid, peer, rec))
	}
	writeJSON(w, map[string]any{
		"entries":      items,
		"scanned_to":   scanned,
		"has_more":     more,
		"read_cursor":  st.ReadCursor(peer),
		"unread_count": st.UnreadCount(peer),
	})
}

func (d *Daemon) chatContactsMap(st *chat.Store) map[string]any {
	var friends, outP, inP []map[string]any
	for _, e := range st.Contacts() {
		item := map[string]any{"peer": e.Peer.String(), "since": e.Since}
		switch e.State {
		case chat.StateMutual:
			item["unread_count"] = st.UnreadCount(e.Peer)
			friends = append(friends, item)
		case chat.StateOutPending:
			outP = append(outP, item)
		case chat.StateInPending:
			item["note"] = e.Note
			inP = append(inP, item)
		}
	}
	if friends == nil {
		friends = []map[string]any{}
	}
	if outP == nil {
		outP = []map[string]any{}
	}
	if inP == nil {
		inP = []map[string]any{}
	}
	return map[string]any{
		"friends":     friends,
		"out_pending": outP,
		"in_pending":  inP,
		"invites":     st.InPendingCount(),
		"unread":      st.TotalUnread(),
	}
}

type chatPeerBody struct {
	Peer      string `json:"peer"`
	Note      string `json:"note,omitempty"`
	Text      string `json:"text,omitempty"`
	Path      string `json:"path,omitempty"`
	ObjectID  string `json:"object_id,omitempty"`
	Name      string `json:"name,omitempty"`
	ScannedTo uint64 `json:"scanned_to,omitempty"`
}

func (d *Daemon) handleChatRequest(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatRequest(r.Context(), ctx.aid, ctx.peer, ctx.note)
	})
}

func (d *Daemon) handleChatAccept(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatAccept(r.Context(), ctx.aid, ctx.peer)
	})
}

func (d *Daemon) handleChatRefuse(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatRefuse(r.Context(), ctx.aid, ctx.peer)
	})
}

func (d *Daemon) handleChatRemove(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatRemove(r.Context(), ctx.aid, ctx.peer)
	})
}

func (d *Daemon) handleChatBlock(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatBlock(ctx.aid, ctx.peer)
	})
}

func (d *Daemon) handleChatSend(w http.ResponseWriter, r *http.Request) {
	var body chatPeerBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := d.execChatSend(r.Context(), r.PathValue("aid"), body.Peer, body.Text, body.Path, body.ObjectID, body.Name)
	if err != nil {
		writeChatErr(w, err)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleChatMarkRead(w http.ResponseWriter, r *http.Request) {
	d.handleChatWrite(w, r, func(ctx aidPeer) (map[string]any, error) {
		return d.execChatMarkRead(ctx.aid, ctx.peer, ctx.scannedTo)
	})
}

type aidPeer struct {
	aid, peer, note string
	scannedTo       uint64
}

func (d *Daemon) handleChatWrite(w http.ResponseWriter, r *http.Request, fn func(aidPeer) (map[string]any, error)) {
	var body chatPeerBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := fn(aidPeer{aid: r.PathValue("aid"), peer: body.Peer, note: body.Note, scannedTo: body.ScannedTo})
	if err != nil {
		writeChatErr(w, err)
		return
	}
	writeJSON(w, out)
}

func writeChatErr(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, chat.ErrNotFriends):
		code = http.StatusForbidden
	case errors.Is(err, chat.ErrSignaling):
		code = http.StatusBadGateway
	case errors.Is(err, chat.ErrNotPending), errors.Is(err, chat.ErrAlready), errors.Is(err, chat.ErrBlocked), errors.Is(err, chat.ErrSelf):
		code = http.StatusConflict
	case errors.Is(err, errNotFound):
		code = http.StatusNotFound
	}
	writeJSONStatus(w, code, map[string]string{"error": err.Error()})
}
