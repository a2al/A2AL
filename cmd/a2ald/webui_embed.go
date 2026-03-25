// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"net/http"
)

//go:embed webui/index.html
var webuiIndex []byte

func (d *daemon) handleWebUIRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(webuiIndex)
}
