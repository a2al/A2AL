// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import "errors"

var (
	// ErrNotFound is returned when a Storage key is missing.
	ErrNotFound = errors.New("a2al: not found")
	// ErrInvalidAddress indicates a malformed or checksum-failed address string.
	ErrInvalidAddress = errors.New("a2al: invalid address")
)
