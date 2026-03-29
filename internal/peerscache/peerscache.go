// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package peerscache persists DHT neighbor UDP dial strings for cold bootstrap.
package peerscache

import (
	"encoding/json"
	"os"
)

const defaultMax = 64

// File is the on-disk JSON shape.
type File struct {
	Peers []string `json:"peers"`
}

// Load reads path; missing file returns nil, nil.
func Load(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Peers, nil
}

// Save writes peers (capped) as JSON.
func Save(path string, peers []string) error {
	if len(peers) > defaultMax {
		peers = peers[:defaultMax]
	}
	b, err := json.MarshalIndent(File{Peers: peers}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
