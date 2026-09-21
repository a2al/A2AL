// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

// The local write face of the object plane.
//
// Objects have two faces and they are deliberately not the same surface:
//
//	read   GET|HEAD /aid/{holder}/cas/{hash}   resource-addressing gateway;
//	                                           any holder, local or remote;
//	                                           remote access decided by
//	                                           decideAccess; no API token.
//	write  POST     /agents/{aid}/cas          local agent API; this node's
//	                                           AIDs only; guarded by the API
//	                                           token; never reaches the wire.
//
// Writing is local by construction. Letting a remote peer push bytes into this
// node's store would turn address resolution into content hosting, which A2AL
// is explicitly not. That is also why upload does not live on /aid/: that
// gateway addresses any AID and intentionally carries no API token, so it is
// the wrong door for an authenticated write to disk.

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

// handleAgentCASUpload streams a request body into the files_root sandbox and
// maps it as an object of aid. The response matches group_object_put so callers
// can use either entrance interchangeably.
//
// Optional query parameter:
//
//	name — original filename, for display only; path components are stripped.
func (d *Daemon) handleAgentCASUpload(w http.ResponseWriter, r *http.Request) {
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	// Only AIDs this node holds. A remote AID is not an error to retry against
	// some other node — this endpoint has no remote form at all.
	if !d.casLocalHolder(aid) {
		http.Error(w, `{"error":"not a local aid"}`, http.StatusNotFound)
		return
	}
	defer r.Body.Close()

	id, size, name, err := d.ingestCASObject(aid, r.Body, r.URL.Query().Get("name"))
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "files_root") {
			// Nowhere to put the bytes is a configuration problem the caller
			// cannot fix by retrying.
			code = http.StatusConflict
		}
		writeJSONStatus(w, code, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, map[string]any{
		"object_id": hex.EncodeToString(id[:]),
		"size":      size,
		"name":      name,
		"url":       group.CASURL(aid, id),
	})
}
