// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
)

func userAgentsDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "a2al", "agents"), nil
}

func agentIdentityPath(aid string) (string, error) {
	dir, err := userAgentsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, aid+".agent.json"), nil
}
