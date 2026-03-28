// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
)

type globalOpts struct {
	API   string
	Token string
	JSON  bool
	Quiet bool
	Args  []string
}

func parseGlobal(argv []string) globalOpts {
	var g globalOpts
	if v := os.Getenv("A2AL_API"); v != "" {
		g.API = v
	}
	if v := os.Getenv("A2AL_TOKEN"); v != "" {
		g.Token = v
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--json":
			g.JSON = true
		case a == "--quiet":
			g.Quiet = true
		case a == "--api" && i+1 < len(argv):
			i++
			g.API = argv[i]
		case a == "--token" && i+1 < len(argv):
			i++
			g.Token = argv[i]
		case strings.HasPrefix(a, "--api="):
			g.API = strings.TrimPrefix(a, "--api=")
		case strings.HasPrefix(a, "--token="):
			g.Token = strings.TrimPrefix(a, "--token=")
		default:
			g.Args = append(g.Args, a)
		}
	}
	return g
}
