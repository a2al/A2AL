// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:webui/dist
var webuiDist embed.FS

func registerWebUIRoutes(mux *http.ServeMux) {
	distFS, err := fs.Sub(webuiDist, "webui/dist")
	if err != nil {
		panic("webui/dist: " + err.Error())
	}
	assetsFS, err := fs.Sub(distFS, "assets")
	if err != nil {
		panic("webui/dist/assets: " + err.Error())
	}
	mux.Handle(
		"GET /assets/",
		http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))),
	)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
}
