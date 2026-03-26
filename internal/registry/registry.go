// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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

// Entry is one registered application agent (not the node identity).
type Entry struct {
	AID            a2al.Address
	ServiceTCP     string
	OpPriv         ed25519.PrivateKey
	DelegationCBOR []byte
	Seq            uint64
	// Topics lists DHT topic strings this agent has registered (for renewal / unregister; spec §5.8).
	Topics []string
}

type diskAgent struct {
	AID                string   `json:"aid"`
	ServiceTCP         string   `json:"service_tcp"`
	OpPrivateKeyHex    string   `json:"op_private_key_hex"`
	DelegationProofHex string   `json:"delegation_proof_hex"`
	Seq                uint64   `json:"seq"`
	Topics             []string `json:"topics,omitempty"`
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
		r.byAID[aid] = &Entry{
			AID:            aid,
			ServiceTCP:     da.ServiceTCP,
			OpPriv:         ed25519.PrivateKey(opRaw),
			DelegationCBOR: proof,
			Seq:            da.Seq,
			Topics:         append([]string(nil), da.Topics...),
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
			Topics:             append([]string(nil), e.Topics...),
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
