// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/internal/registry"
)

const (
	raAIDFailBan        = 5
	raJoinFailRevoke    = 15
	raIPWindow          = 10 * time.Second
	raIPMax             = 8
	raMaxAIDFailTracked = 1024
	raMaxIPTracked      = 512
)

type remoteAdminEvent struct {
	AID  string `json:"aid"`
	Time string `json:"time"`
	IP   string `json:"ip"`
}

type remoteAdminDisk struct {
	Enabled bool                `json:"enabled"`
	ACL     *registry.ACLPolicy `json:"acl"`
	LastOK  *remoteAdminEvent   `json:"last_ok,omitempty"`
	LastBad *remoteAdminEvent   `json:"last_bad_secret,omitempty"`
}

type raWindow struct {
	windowEnd time.Time
	count     int
}

type remoteAdminRuntime struct {
	mu          sync.Mutex
	path        string
	disk        remoteAdminDisk
	aidFails    map[string]int
	ipBucket    map[string]*raWindow
	secretFails int // consecutive wrong passwords since last successful access
	okOnce      map[string]struct{}
}

func (d *Daemon) initRemoteAdmin() {
	d.ra = newRemoteAdminRuntime(d.dataDir)
	if err := d.ra.load(); err != nil && d.log != nil {
		d.log.Warn("remote_admin load", "err", err)
	}
}

func (d *Daemon) remoteAdminEnabled() bool {
	return d.ra != nil && d.ra.enabled()
}

func (d *Daemon) remoteAdminServiceTCP() string {
	addr := ""
	if d.cfg != nil {
		addr = strings.TrimSpace(d.cfg.APIAddr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "127.0.0.1:2121"
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.IsLoopback() {
		return addr
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func newRemoteAdminRuntime(dataDir string) *remoteAdminRuntime {
	return &remoteAdminRuntime{
		path:     filepath.Join(dataDir, "remote_admin.json"),
		aidFails: make(map[string]int),
		ipBucket: make(map[string]*raWindow),
		okOnce:   make(map[string]struct{}),
		disk: remoteAdminDisk{
			ACL: emptyNodeACL(),
		},
	}
}

func emptyNodeACL() *registry.ACLPolicy {
	return &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
}

func (s *remoteAdminRuntime) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var disk remoteAdminDisk
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	if disk.ACL == nil {
		disk.ACL = emptyNodeACL()
	}
	disk.ACL.Default = registry.ACLDefaultDeny
	disk.ACL.Paid = false
	if err := disk.ACL.Validate(); err != nil {
		disk.ACL = emptyNodeACL()
	}
	s.mu.Lock()
	s.disk = disk
	s.mu.Unlock()
	return nil
}

func (s *remoteAdminRuntime) persistLocked() error {
	s.disk.ACL.Default = registry.ACLDefaultDeny
	s.disk.ACL.Paid = false
	b, err := json.MarshalIndent(s.disk, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *remoteAdminRuntime) enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk.Enabled
}

func (s *remoteAdminRuntime) snapshot() remoteAdminDisk {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := remoteAdminDisk{Enabled: s.disk.Enabled}
	out.ACL = cloneACL(s.disk.ACL)
	if s.disk.LastOK != nil {
		cp := *s.disk.LastOK
		out.LastOK = &cp
	}
	if s.disk.LastBad != nil {
		cp := *s.disk.LastBad
		out.LastBad = &cp
	}
	return out
}

func (s *remoteAdminRuntime) setEnabled(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disk.Enabled = on
	if !on {
		s.secretFails = 0
	}
	return s.persistLocked()
}

func (s *remoteAdminRuntime) allows(remote a2al.Address, secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk.ACL.Allows(remote, secret)
}

func (s *remoteAdminRuntime) decide(remote a2al.Address, secret string, src net.Addr) (ok bool, joinRevoked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.disk.Enabled {
		return true, false
	}
	if s.disk.ACL == nil {
		s.disk.ACL = emptyNodeACL()
	}
	ip := addrIP(src)
	if s.disk.ACL.Allows(remote, secret) {
		if usedJoinPassword(s.disk.ACL, remote, secret) {
			s.addAllowLocked(remote)
		}
		delete(s.aidFails, remote.String())
		s.secretFails = 0
		return true, false
	}
	if secret == "" {
		return false, false
	}
	ipLimited := ip != "" && !s.ipOKLocked(ip)
	s.recordBadSecretLocked(remote, ip)
	if !ipLimited {
		aidKey := remote.String()
		s.aidFails[aidKey]++
		if s.aidFails[aidKey] >= raAIDFailBan {
			s.addDenyLocked(remote)
			delete(s.aidFails, aidKey)
		}
		if len(s.aidFails) > raMaxAIDFailTracked {
			s.aidFails = make(map[string]int)
		}
	}
	if !joinPasswordSet(s.disk.ACL) {
		_ = s.persistLocked()
		return false, false
	}
	s.secretFails++
	if s.secretFails >= raJoinFailRevoke {
		s.clearJoinLocked()
		s.secretFails = 0
		_ = s.persistLocked()
		return false, true
	}
	_ = s.persistLocked()
	return false, false
}

func joinPasswordSet(p *registry.ACLPolicy) bool {
	if p == nil {
		return false
	}
	for _, e := range p.Allow {
		if e.AID == "" && e.Secret != "" {
			return true
		}
	}
	return false
}

func (s *remoteAdminRuntime) clearJoinLocked() {
	next := cloneACL(s.disk.ACL)
	next.Default = registry.ACLDefaultDeny
	kept := next.Allow[:0]
	for _, e := range next.Allow {
		if e.AID != "" {
			kept = append(kept, e)
		}
	}
	next.Allow = kept
	s.disk.ACL = next
}

func (s *remoteAdminRuntime) ipOKLocked(ip string) bool {
	now := time.Now()
	if len(s.ipBucket) > raMaxIPTracked {
		for k, e := range s.ipBucket {
			if now.After(e.windowEnd) {
				delete(s.ipBucket, k)
			}
		}
		if len(s.ipBucket) > raMaxIPTracked {
			s.ipBucket = make(map[string]*raWindow)
		}
	}
	e := s.ipBucket[ip]
	if e == nil || now.After(e.windowEnd) {
		s.ipBucket[ip] = &raWindow{windowEnd: now.Add(raIPWindow), count: 1}
		return true
	}
	e.count++
	return e.count <= raIPMax
}

func (s *remoteAdminRuntime) recordBadSecretLocked(remote a2al.Address, ip string) {
	s.disk.LastBad = &remoteAdminEvent{
		AID:  remote.String(),
		Time: time.Now().UTC().Format(time.RFC3339),
		IP:   ip,
	}
}

func (s *remoteAdminRuntime) noteOK(connKey, aid, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.disk.Enabled {
		return
	}
	if _, seen := s.okOnce[connKey]; seen {
		return
	}
	s.okOnce[connKey] = struct{}{}
	s.secretFails = 0
	s.disk.LastOK = &remoteAdminEvent{
		AID:  aid,
		Time: time.Now().UTC().Format(time.RFC3339),
		IP:   ip,
	}
	_ = s.persistLocked()
}

func (s *remoteAdminRuntime) addAllowLocked(remote a2al.Address) {
	aidStr := remote.String()
	for _, ent := range s.disk.ACL.Allow {
		if strings.EqualFold(ent.AID, aidStr) {
			return
		}
	}
	next := cloneACL(s.disk.ACL)
	next.Default = registry.ACLDefaultDeny
	next.Allow = append(next.Allow, registry.ACLEntry{ID: newACLEntryID(), AID: aidStr})
	if err := next.Validate(); err != nil {
		return
	}
	s.disk.ACL = next
	_ = s.persistLocked()
}

func (s *remoteAdminRuntime) addDenyLocked(remote a2al.Address) {
	aidStr := remote.String()
	next := cloneACL(s.disk.ACL)
	next.Default = registry.ACLDefaultDeny
	kept := next.Allow[:0]
	for _, ent := range next.Allow {
		if ent.AID != "" && strings.EqualFold(ent.AID, aidStr) {
			continue
		}
		kept = append(kept, ent)
	}
	next.Allow = kept
	for _, ent := range next.Deny {
		if strings.EqualFold(ent.AID, aidStr) {
			s.disk.ACL = next
			_ = s.persistLocked()
			return
		}
	}
	next.Deny = append(next.Deny, registry.ACLEntry{ID: newACLEntryID(), AID: aidStr})
	if err := next.Validate(); err != nil {
		return
	}
	s.disk.ACL = next
	_ = s.persistLocked()
}

func (s *remoteAdminRuntime) addEntry(list string, req aclEntryReq) (registry.ACLEntry, error) {
	ent := registry.ACLEntry{ID: newACLEntryID(), AID: req.AID}
	if list == "allow" && req.AID == "" {
		ent.Secret = req.Secret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneACL(s.disk.ACL)
	next.Default = registry.ACLDefaultDeny
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
		return registry.ACLEntry{}, err
	}
	s.disk.ACL = next
	if err := s.persistLocked(); err != nil {
		return registry.ACLEntry{}, err
	}
	return ent, nil
}

func (s *remoteAdminRuntime) deleteEntry(list, id string) error {
	if id == "" {
		return errNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disk.ACL == nil {
		return errNotFound
	}
	next := cloneACL(s.disk.ACL)
	next.Default = registry.ACLDefaultDeny
	var found bool
	if list == "deny" {
		next.Deny, found = filterACLEntry(s.disk.ACL.Deny, id)
	} else {
		next.Allow, found = filterACLEntry(s.disk.ACL.Allow, id)
	}
	if !found {
		return errNotFound
	}
	s.disk.ACL = next
	return s.persistLocked()
}

func addrIP(src net.Addr) string {
	if src == nil {
		return ""
	}
	switch a := src.(type) {
	case *net.UDPAddr:
		if a.IP != nil {
			return a.IP.String()
		}
	case *net.TCPAddr:
		if a.IP != nil {
			return a.IP.String()
		}
	}
	host, _, err := net.SplitHostPort(src.String())
	if err != nil {
		return src.String()
	}
	return host
}

func (d *Daemon) handleRemoteAdminGet(w http.ResponseWriter, r *http.Request) {
	if d.ra == nil {
		writeJSON(w, map[string]any{
			"enabled":         false,
			"acl":             aclForEditor(emptyNodeACL()),
			"last_ok":         nil,
			"last_bad_secret": nil,
			"token_suggested": d.cfg == nil || d.cfg.APIToken == "",
		})
		return
	}
	snap := d.ra.snapshot()
	writeJSON(w, map[string]any{
		"enabled":         snap.Enabled,
		"acl":             aclForEditor(snap.ACL),
		"last_ok":         snap.LastOK,
		"last_bad_secret": snap.LastBad,
		"token_suggested": d.cfg == nil || d.cfg.APIToken == "",
	})
}

type remoteAdminPatchReq struct {
	Enabled *bool `json:"enabled"`
}

func (d *Daemon) handleRemoteAdminPatch(w http.ResponseWriter, r *http.Request) {
	var req remoteAdminPatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.Enabled == nil || d.ra == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "enabled required"})
		return
	}
	if err := d.ra.setEnabled(*req.Enabled); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "persist failed"})
		return
	}
	writeJSON(w, map[string]string{"status": "updated"})
}

func (d *Daemon) handleRemoteAdminAllowPost(w http.ResponseWriter, r *http.Request) {
	d.handleRemoteAdminListPost(w, r, "allow")
}

func (d *Daemon) handleRemoteAdminDenyPost(w http.ResponseWriter, r *http.Request) {
	d.handleRemoteAdminListPost(w, r, "deny")
}

func (d *Daemon) handleRemoteAdminListPost(w http.ResponseWriter, r *http.Request, list string) {
	var req aclEntryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if d.ra == nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	ent, err := d.ra.addEntry(list, req)
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

func (d *Daemon) handleRemoteAdminAllowDelete(w http.ResponseWriter, r *http.Request) {
	d.handleRemoteAdminListDelete(w, r, "allow")
}

func (d *Daemon) handleRemoteAdminDenyDelete(w http.ResponseWriter, r *http.Request) {
	d.handleRemoteAdminListDelete(w, r, "deny")
}

func (d *Daemon) handleRemoteAdminListDelete(w http.ResponseWriter, r *http.Request, list string) {
	if d.ra == nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := d.ra.deleteEntry(list, r.PathValue("id")); err != nil {
		writeACLError(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "deleted"})
}
