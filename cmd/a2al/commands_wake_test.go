// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import "testing"

func TestWakeArgsWantHelp(t *testing.T) {
	if !wakeArgsWantHelp([]string{"test", "--help"}) {
		t.Fatal("test --help")
	}
	if !wakeArgsWantHelp([]string{"-h"}) {
		t.Fatal("-h")
	}
	if wakeArgsWantHelp([]string{"test"}) {
		t.Fatal("test alone")
	}
}
