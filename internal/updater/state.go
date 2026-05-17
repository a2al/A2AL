// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package updater implements a2ald self-update logic: periodic version checks,
// atomic binary replacement, startup-counter-based rollback, and retraction
// detection. See doc-local/a2ald 自动更新设计.md for the full design.
package updater

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const stateSchema = 1

// Status values stored in update_state.json.
const (
	StatusPending        = "pending"         // binary replaced, health not yet confirmed
	StatusOK             = "ok"              // new binary confirmed healthy
	StatusRolledBack     = "rolled_back"     // rollback executed, old binary restored
	StatusRollbackFailed = "rollback_failed" // terminal: .old unavailable/corrupt, no rollback possible
)

// UpdateState is persisted as <data-dir>/update_state.json.
// It is written atomically before os.Exit(0) and read at startup.
type UpdateState struct {
	Schema            int       `json:"schema"`
	Status            string    `json:"status"`
	OldVersion        string    `json:"old_version"`
	NewVersion        string    `json:"new_version"`
	OldChecksumSHA256 string    `json:"old_checksum_sha256"`
	ReplacedAt        time.Time `json:"replaced_at"`
	Attempts          int       `json:"attempts"`
	LastAttemptAt     time.Time `json:"last_attempt_at,omitempty"`
	RolledBackAt      time.Time `json:"rolled_back_at,omitempty"`
}

func stateFilePath(dataDir string) string {
	return filepath.Join(dataDir, "update_state.json")
}

// ReadState reads update_state.json. Returns nil (no error) when file is absent.
func ReadState(dataDir string) (*UpdateState, error) {
	data, err := os.ReadFile(stateFilePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s UpdateState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// WriteState atomically writes state via a temp file + rename.
func WriteState(dataDir string, s *UpdateState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := stateFilePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, stateFilePath(dataDir))
}
