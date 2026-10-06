// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

const casPrefetchMax = 32 << 20

var errCASNoLive = errors.New("cas: no live path")

func (d *Daemon) handleAgentCASGet(w http.ResponseWriter, r *http.Request) {
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	if !d.casLocalHolder(aid) {
		http.Error(w, `{"error":"not a local aid"}`, http.StatusNotFound)
		return
	}
	id, err := parseHex32(r.PathValue("object_id"))
	if err != nil {
		http.Error(w, `{"error":"bad object_id"}`, http.StatusBadRequest)
		return
	}
	var hint a2al.Address
	if h := strings.TrimSpace(r.URL.Query().Get("hint")); h != "" {
		hint, err = a2al.ParseAddress(h)
		if err != nil {
			http.Error(w, `{"error":"bad hint"}`, http.StatusBadRequest)
			return
		}
	}
	force := r.URL.Query().Get("force") == "1" || strings.EqualFold(r.URL.Query().Get("force"), "true")
	if _, _, err := d.ensureObjectLocal(r.Context(), aid, id, hint, force, false, ""); err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	d.serveCASFile(w, aid, id, r.Method)
}

func (d *Daemon) ensureObjectLocal(ctx context.Context, aid a2al.Address, id [32]byte, hint a2al.Address, force, liveOnly bool, tokenOverride string) (string, int64, error) {
	if !force {
		if p, sz, ok := d.lookupLocalObject(aid, id); ok {
			d.noteLocalCASRedeem(aid, id, hint)
			return p, sz, nil
		}
	}
	rec, _ := d.casRec(aid, id)
	token := strings.TrimSpace(tokenOverride)
	if token == "" {
		token = rec.Grant
	}
	holders := d.casHintHolders(aid, id, hint)
	if len(holders) == 0 {
		return "", 0, errors.New("cas: no holder known")
	}
	dest, err := d.casFetchDest(id)
	if err != nil {
		return "", 0, err
	}
	var last error
	for _, h := range holders {
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}
		if p, sz, ok := d.lookupLocalObject(h, id); ok {
			if err := d.mapObject(aid, id, p, sz); err != nil {
				return "", 0, err
			}
			d.rememberObjectRef(aid, id, rec.Grant, h, sz)
			d.noteCASServed(h, aid, id)
			return p, sz, nil
		}
		if liveOnly {
			last = d.fetchCASToFileLive(ctx, aid, h, id, dest, token)
		} else if d.connPool != nil && d.connPool.getLive(aid, h) != nil {
			last = d.fetchCASToFileLive(ctx, aid, h, id, dest, token)
			if last != nil {
				last = d.fetchCASToFile(ctx, aid, h, id, dest, token)
			}
		} else {
			last = d.fetchCASToFile(ctx, aid, h, id, dest, token)
		}
		if last != nil {
			continue
		}
		st, err := os.Stat(dest)
		if err != nil {
			last = err
			continue
		}
		if err := d.mapObject(aid, id, dest, st.Size()); err != nil {
			return "", 0, err
		}
		return dest, st.Size(), nil
	}
	if last == nil {
		last = errors.New("cas: no holder known")
	}
	return "", 0, last
}

func (d *Daemon) casFetchDest(id [32]byte) (string, error) {
	dir, err := d.casIngestDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hex.EncodeToString(id[:])+".bin"), nil
}

// noteLocalCASRedeem records that aid already holds id, as a redeem against
// another local holder (hint or stored author). Identity get hits the local
// shortcut after prefetch, so mapObject's noteCASServed would otherwise never run.
func (d *Daemon) noteLocalCASRedeem(aid a2al.Address, id [32]byte, hint a2al.Address) {
	holder := hint
	if holder == (a2al.Address{}) {
		if rec, ok := d.casRec(aid, id); ok {
			if a, err := a2al.ParseAddress(rec.Author); err == nil {
				holder = a
			}
		}
	}
	if holder == aid || !d.casLocalHolder(holder) {
		return
	}
	d.noteCASServed(holder, aid, id)
}

func (d *Daemon) casHintHolders(local a2al.Address, id [32]byte, extra ...a2al.Address) []a2al.Address {
	seen := map[a2al.Address]struct{}{local: {}, {}: {}}
	var out []a2al.Address
	add := func(a a2al.Address) {
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range extra {
		add(a)
	}
	if rec, ok := d.casRec(local, id); ok {
		if a, err := a2al.ParseAddress(rec.Author); err == nil {
			add(a)
		}
	}
	if d.groups == nil || d.alignPeers == nil {
		return out
	}
	metas, err := d.groups.List(local)
	if err != nil {
		return out
	}
	n := 0
	for i, m := range metas {
		if i >= 8 || n >= 4 {
			break
		}
		s, err := d.groups.Open(local, m.GroupID)
		if err != nil {
			continue
		}
		ms, err := s.Members()
		if err != nil {
			continue
		}
		for mem, role := range ms.All() {
			if n >= 4 {
				break
			}
			if role < group.RoleMember {
				continue
			}
			if _, _, ok := d.replicaHead(local, mem, m.GroupID); !ok {
				continue
			}
			add(mem)
			n++
		}
	}
	return out
}

func (d *Daemon) prefetchObject(local a2al.Address, id [32]byte, hints ...a2al.Address) {
	rec, _ := d.casRec(local, id)
	if rec.Size > casPrefetchMax {
		return
	}
	var hint a2al.Address
	if len(hints) > 0 {
		hint = hints[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, _ = d.ensureObjectLocal(ctx, local, id, hint, false, true, "")
}

func (d *Daemon) settleCASWanted(ctx context.Context, local, remote a2al.Address) {
	idx, err := d.loadCasIndex(local)
	if err != nil {
		return
	}
	for k, rec := range idx.recs {
		if ctx.Err() != nil {
			return
		}
		if rec.Grant == "" || rec.Size > casPrefetchMax {
			continue
		}
		if rec.Path != "" {
			if st, err := os.Stat(rec.Path); err == nil && !st.IsDir() {
				continue
			}
		}
		author, err := a2al.ParseAddress(rec.Author)
		if err != nil || author != remote {
			continue
		}
		id, err := parseHex32(k)
		if err != nil {
			continue
		}
		_, _, _ = d.ensureObjectLocal(ctx, local, id, remote, false, true, "")
	}
}
