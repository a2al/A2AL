// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package registry persists REST-registered agents (operational key + TCP target).
package registry

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"github.com/a2al/a2al"
)

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
}

type diskAgent struct {
	AID                string          `json:"aid"`
	ServiceTCP         string          `json:"service_tcp"`
	OpPrivateKeyHex    string          `json:"op_private_key_hex"`
	DelegationProofHex string          `json:"delegation_proof_hex"`
	Seq                uint64          `json:"seq"`
	Services           []ServiceRecord `json:"services,omitempty"`
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
