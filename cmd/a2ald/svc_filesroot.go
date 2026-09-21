// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/a2al/a2al/config"
)

// ensureFilesRootConfig creates filesRoot and writes files_root into
// dataDir/config.toml when the key is still empty. Existing values are kept.
func ensureFilesRootConfig(dataDir, filesRoot string) error {
	if err := os.MkdirAll(filesRoot, 0o755); err != nil {
		return err
	}
	cfgPath := filepath.Join(dataDir, "config.toml")
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		cfg = config.Default()
	}
	if strings.TrimSpace(cfg.FilesRoot) != "" {
		return nil
	}
	cfg.FilesRoot = filesRoot
	return config.Save(cfgPath, cfg)
}
