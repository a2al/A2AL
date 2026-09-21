// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al/config"
)

func TestEnsureFilesRootConfig(t *testing.T) {
	dataDir := t.TempDir()
	filesRoot := filepath.Join(t.TempDir(), "files")
	if err := ensureFilesRootConfig(dataDir, filesRoot); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filesRoot)
	if err != nil || !st.IsDir() {
		t.Fatalf("filesRoot: %v", err)
	}
	cfg, err := config.LoadFile(filepath.Join(dataDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FilesRoot != filesRoot {
		t.Fatalf("FilesRoot=%q", cfg.FilesRoot)
	}

	keep := filepath.Join(t.TempDir(), "keep")
	cfg.FilesRoot = keep
	if err := config.Save(filepath.Join(dataDir, "config.toml"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := ensureFilesRootConfig(dataDir, filesRoot); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.LoadFile(filepath.Join(dataDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FilesRoot != keep {
		t.Fatalf("overwrote existing FilesRoot: %q", cfg.FilesRoot)
	}
}
