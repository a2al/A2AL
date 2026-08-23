// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package registry persists REST-registered agents (operational key + TCP target).
package registry

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/a2al/a2al"
)

var (
	ErrBadACLDefault   = errors.New("acl default must be public or deny")
	ErrDenyNeedsAID    = errors.New("acl deny entry requires aid")
	ErrBadACLAID       = errors.New("acl entry has bad aid")
	ErrJoinNeedsSecret = errors.New("acl join password requires secret")
	ErrNamedNoSecret   = errors.New("acl named allow entry cannot have secret")
	ErrDupJoinPassword = errors.New("acl allows only one join password")
	ErrDupACLAID       = errors.New("acl aid already listed")
	ErrACLBothLists    = errors.New("acl aid cannot be in allow and deny")
)

// ProfileOverride holds user-supplied agent profile fields.
// Non-zero fields take precedence over values inferred from Services when
// assembling the RecType 0x02 sovereign record payload.
type ProfileOverride struct {
	Name       string         `json:"name,omitempty"`
	Brief      string         `json:"brief,omitempty"`
	Protocols  []string       `json:"protocols,omitempty"`
	Skills     []string       `json:"skills,omitempty"`
	CardHash   []byte         `json:"card_hash,omitempty"`
	Modalities []string       `json:"modalities,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
}

// ServiceRecord persists a published service (full payload) for auto-renewal.
// JSON key is "services" to align with user-facing terminology.
type ServiceRecord struct {
	Topic     string         `json:"topic"`
	Name      string         `json:"name,omitempty"`
	Protocols []string       `json:"protocols,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Brief     string         `json:"brief,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	TTL       uint32         `json:"ttl,omitempty"`
}

// Entry is one registered application agent (not the node identity).
type Entry struct {
	AID            a2al.Address
	ServiceTCP     string
	OpPriv         ed25519.PrivateKey
	DelegationCBOR []byte
	Seq            uint64
	// Services lists published service payloads for auto-renewal (user-facing name for DHT topics).
	Services []ServiceRecord
	// Profile holds user-supplied overrides for the RecType 0x02 sovereign record.
	// Nil means use inferred values from Services only.
	Profile *ProfileOverride
	// DemoActive records that the built-in demo HTTP server is running for this agent.
	// Set by demo start; cleared by demo stop. On daemon restart, any entry with
	// DemoActive=true is recovered by re-starting the demo server automatically.
	DemoActive bool
	// ACL is the local data-plane policy for service_tcp. Nil means public.
	ACL *ACLPolicy
}

// ACLDefault is the fallback when neither deny nor allow matches.
type ACLDefault string

const (
	ACLDefaultPublic ACLDefault = "public"
	ACLDefaultDeny   ACLDefault = "deny"
)

// ACLEntry is one allow/deny rule.
// Empty AID + Secret is the single join password (allow only).
// Named AID entries do not carry a secret. BindOnUse is stored but unused.
type ACLEntry struct {
	ID        string `json:"id"`
	AID       string `json:"aid,omitempty"`
	Secret    string `json:"secret,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	MaxUses   int    `json:"max_uses,omitempty"`
	BindOnUse bool   `json:"bind_on_use,omitempty"`
}

// ACLPolicy is the per-agent access policy. Decision order is fixed:
// deny hit → reject; else allow hit → permit; else Paid+auth (later); else Default.
type ACLPolicy struct {
	Default ACLDefault `json:"default,omitempty"`
	Paid    bool       `json:"paid,omitempty"` // reserved; not a third default
	Deny    []ACLEntry `json:"deny,omitempty"`
	Allow   []ACLEntry `json:"allow,omitempty"`
}

// Allows reports whether remote may use service_tcp.
// secret is the join password from AccessToken; ignored unless an allow entry has Secret set.
func (p *ACLPolicy) Allows(remote a2al.Address, secret string) bool {
	if p == nil {
		return true
	}
	for _, e := range p.Deny {
		if e.matchesAID(remote) {
			return false
		}
	}
	for _, e := range p.Allow {
		if e.matches(remote, secret) {
			return true
		}
	}
	return p.Default != ACLDefaultDeny
}

func (e ACLEntry) matchesAID(remote a2al.Address) bool {
	if e.AID == "" {
		return true
	}
	aid, err := a2al.ParseAddress(e.AID)
	return err == nil && aid == remote
}

func (e ACLEntry) matches(remote a2al.Address, secret string) bool {
	if e.AID != "" && !e.matchesAID(remote) {
		return false
	}
	if e.Secret != "" && e.Secret != secret {
		return false
	}
	return true
}

// Validate checks policy constraints. Empty/nil policy is valid (public).
func (p *ACLPolicy) Validate() error {
	if p == nil {
		return nil
	}
	switch p.Default {
	case "", ACLDefaultPublic, ACLDefaultDeny:
	default:
		return ErrBadACLDefault
	}
	seenDeny := map[string]struct{}{}
	for _, e := range p.Deny {
		if e.AID == "" {
			return ErrDenyNeedsAID
		}
		if _, err := a2al.ParseAddress(e.AID); err != nil {
			return ErrBadACLAID
		}
		k := strings.ToLower(e.AID)
		if _, ok := seenDeny[k]; ok {
			return ErrDupACLAID
		}
		seenDeny[k] = struct{}{}
	}
	seenAllow := map[string]struct{}{}
	joinN := 0
	for _, e := range p.Allow {
		if e.AID == "" {
			if e.Secret == "" {
				return ErrJoinNeedsSecret
			}
			joinN++
			if joinN > 1 {
				return ErrDupJoinPassword
			}
			continue
		}
		if e.Secret != "" {
			return ErrNamedNoSecret
		}
		if _, err := a2al.ParseAddress(e.AID); err != nil {
			return ErrBadACLAID
		}
		k := strings.ToLower(e.AID)
		if _, ok := seenAllow[k]; ok {
			return ErrDupACLAID
		}
		if _, ok := seenDeny[k]; ok {
			return ErrACLBothLists
		}
		seenAllow[k] = struct{}{}
	}
	return nil
}

type diskAgent struct {
	AID                string           `json:"aid"`
	ServiceTCP         string           `json:"service_tcp"`
	OpPrivateKeyHex    string           `json:"op_private_key_hex"`
	DelegationProofHex string           `json:"delegation_proof_hex"`
	Seq                uint64           `json:"seq"`
	Services           []ServiceRecord  `json:"services,omitempty"`
	Profile            *ProfileOverride `json:"profile,omitempty"`
	DemoActive         bool             `json:"demo_active,omitempty"`
	ACL                *ACLPolicy       `json:"acl,omitempty"`
	// Topics is a legacy field (pre-v1.1); loaded for migration, never written.
	Topics []string `json:"topics,omitempty"`
}

type diskFile struct {
	Agents []diskAgent `json:"agents"`
}

// Registry is a file-backed map of agent AID → registration.
type Registry struct {
	mu    sync.RWMutex
	path  string
	byAID map[a2al.Address]*Entry
}

// New returns an empty registry; call Load to populate from disk.
func New(path string) *Registry {
	return &Registry{
		path:  path,
		byAID: make(map[a2al.Address]*Entry),
	}
}

// Load reads agents.json; missing file is OK.
func Load(path string) (*Registry, error) {
	r := New(path)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	var df diskFile
	if err := json.Unmarshal(b, &df); err != nil {
		return nil, err
	}
	for _, da := range df.Agents {
		aid, err := a2al.ParseAddress(da.AID)
		if err != nil {
			continue
		}
		opRaw, err := hex.DecodeString(da.OpPrivateKeyHex)
		if err != nil || len(opRaw) != ed25519.PrivateKeySize {
			continue
		}
		proof, err := hex.DecodeString(da.DelegationProofHex)
		if err != nil {
			continue
		}
		svcs := append([]ServiceRecord(nil), da.Services...)
		// Migrate legacy topics list (name-only) to ServiceRecord if services absent.
		if len(svcs) == 0 {
			for _, t := range da.Topics {
				svcs = append(svcs, ServiceRecord{Topic: t})
			}
		}
		r.byAID[aid] = &Entry{
			AID:            aid,
			ServiceTCP:     da.ServiceTCP,
			OpPriv:         ed25519.PrivateKey(opRaw),
			DelegationCBOR: proof,
			Seq:            da.Seq,
			Services:       svcs,
			Profile:        da.Profile,
			DemoActive:     da.DemoActive,
			ACL:            da.ACL,
		}
	}
	return r, nil
}

// Put adds or replaces an entry (in-memory + Save).
func (r *Registry) Put(e *Entry) error {
	r.mu.Lock()
	r.byAID[e.AID] = e
	r.mu.Unlock()
	return r.Save()
}

// Delete removes an agent; no-op if missing.
func (r *Registry) Delete(aid a2al.Address) error {
	r.mu.Lock()
	delete(r.byAID, aid)
	r.mu.Unlock()
	return r.Save()
}

// Get returns a copy-safe view (caller must not mutate OpPriv).
func (r *Registry) Get(aid a2al.Address) *Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byAID[aid]
}

// List returns all entries (for GET /agents).
func (r *Registry) List() []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Entry, 0, len(r.byAID))
	for _, e := range r.byAID {
		out = append(out, e)
	}
	return out
}

// Save writes agents.json atomically.
func (r *Registry) Save() error {
	r.mu.RLock()
	list := make([]*Entry, 0, len(r.byAID))
	for _, e := range r.byAID {
		list = append(list, e)
	}
	r.mu.RUnlock()

	df := diskFile{Agents: make([]diskAgent, 0, len(list))}
	for _, e := range list {
		df.Agents = append(df.Agents, diskAgent{
			AID:                e.AID.String(),
			ServiceTCP:         e.ServiceTCP,
			OpPrivateKeyHex:    hex.EncodeToString(e.OpPriv),
			DelegationProofHex: hex.EncodeToString(e.DelegationCBOR),
			Seq:                e.Seq,
			Services:           append([]ServiceRecord(nil), e.Services...),
			Profile:            e.Profile,
			DemoActive:         e.DemoActive,
			ACL:                e.ACL,
		})
	}
	b, err := json.MarshalIndent(df, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
