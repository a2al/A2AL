// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// a2al is the command-line client for the local a2ald daemon (REST API only).
package main

import (
	"fmt"
	"os"
)

func main() {
	argv := os.Args[1:]
	g := parseGlobal(argv)
	if len(g.Args) == 0 {
		cmdHelp()
		os.Exit(1)
	}
	cmd := g.Args[0]
	args := g.Args[1:]
	cli := newClient(g.API, g.Token, true)

	switch cmd {
	case "help", "-h", "--help":
		cmdHelp()
	case "status":
		cmdStatus(cli, g, args)
	case "register":
		cmdRegister(cli, g, args)
	case "publish":
		cmdPublish(cli, g, args)
	case "unpublish":
		cmdUnpublish(cli, g, args)
	case "search":
		cmdSearch(cli, g, args)
	case "info":
		cmdInfo(cli, g, args)
	case "get":
		cmdGet(cli, g, args)
	case "post":
		cmdPost(cli, g, args)
	case "agents":
		cmdAgents(cli, g, args)
	case "identity":
		cmdIdentity(cli, g, args)
	case "resolve":
		cmdResolve(cli, g, args)
	case "connect":
		cmdConnect(cli, g, args)
	case "note":
		cmdNote(cli, g, args)
	case "config":
		cmdConfig(cli, g, args)
	default:
		fmt.Fprintf(os.Stderr, "a2al: unknown command %q (try a2al help)\n", cmd)
		os.Exit(1)
	}
}
