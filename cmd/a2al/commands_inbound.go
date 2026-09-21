// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const inboundBindUsage = `usage: a2al inbound bind --addr <host:port> [--aid <local-aid>]
  Attach a local HTTP listen to an AID so others can fetch it.
  <addr>: host:port  or  http://host:port  (path not allowed).
  Do not use this daemon's api_addr.`

var (
	errNeedAddr       = errors.New("need --addr host:port")
	errServiceTCPPath = errors.New("service_tcp cannot contain a path — use host:port or https://host:port")
)

type inboundBindResult struct {
	AID          string
	ServiceTCP   string
	InboundURL   string
	InboundV1URL string
	Share        string
}

func cmdInbound(c *Client, g globalOpts, args []string) {
	if len(args) == 0 {
		fatalf("%s", inboundBindUsage)
	}
	switch args[0] {
	case "bind":
		cmdInboundBind(c, g, args[1:])
	default:
		fatalf("unknown inbound subcommand %q\n%s", args[0], inboundBindUsage)
	}
}

func cmdInboundBind(c *Client, g globalOpts, args []string) {
	res, err := inboundBind(c, flagString(args, "--addr"), flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{
			"aid":            res.AID,
			"service_tcp":    res.ServiceTCP,
			"inbound_url":    res.InboundURL,
			"inbound_v1_url": res.InboundV1URL,
			"share":          res.Share,
		})
		return
	}
	if g.Quiet {
		fmt.Println(res.InboundURL)
		return
	}
	fmt.Printf("bound %s → %s\n", res.AID, res.ServiceTCP)
	fmt.Println(res.InboundURL)
	fmt.Println(res.InboundV1URL)
	fmt.Println()
	fmt.Println(res.Share)
}

func inboundBind(c *Client, addr, aidFlag string) (inboundBindResult, error) {
	dialAddr, err := serviceTCPDialAddr(addr)
	if err != nil {
		return inboundBindResult{}, err
	}
	aids, err := listAgentAIDs(c)
	if err != nil {
		return inboundBindResult{}, err
	}
	aid, err := pickInboundAID(aids, aidFlag)
	if err != nil {
		return inboundBindResult{}, err
	}
	if hp, err := canonicalHostPort(addr); err == nil {
		for _, api := range daemonAPIHostPorts(c) {
			if hp == api {
				return inboundBindResult{}, fmt.Errorf("service_tcp cannot be this daemon's api_addr (%s); that is the control plane, not your HTTP service", addr)
			}
		}
	}
	if err := probeServiceTCP(dialAddr, 2*time.Second); err != nil {
		return inboundBindResult{}, err
	}
	body := map[string]any{"service_tcp": addr}
	if id, err := loadAgentIdentity(aid); err == nil && id.OperationalPrivateKeyHex != "" {
		body["operational_private_key_hex"] = id.OperationalPrivateKeyHex
	}
	if _, _, err := c.DoRequest(http.MethodPatch, "/agents/"+url.PathEscape(aid), body, new(map[string]any)); err != nil {
		return inboundBindResult{}, err
	}
	if id, err := loadAgentIdentity(aid); err == nil {
		id.ServiceTCP = addr
		_ = saveAgentIdentity(id)
	}
	root, v1 := inboundURLs(c.Base, aid)
	return inboundBindResult{
		AID:          aid,
		ServiceTCP:   addr,
		InboundURL:   root,
		InboundV1URL: v1,
		Share:        inboundShareText(aid, c.Base),
	}, nil
}

func listAgentAIDs(c *Client) ([]string, error) {
	var wrap struct {
		Agents []struct {
			AID string `json:"aid"`
		} `json:"agents"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/agents", nil, &wrap); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(wrap.Agents))
	for _, a := range wrap.Agents {
		if a.AID != "" {
			out = append(out, a.AID)
		}
	}
	return out, nil
}

func pickInboundAID(aids []string, flag string) (string, error) {
	if flag != "" {
		for _, a := range aids {
			if a == flag {
				return flag, nil
			}
		}
		return "", fmt.Errorf("AID %s is not registered on this daemon", flag)
	}
	switch len(aids) {
	case 0:
		return "", fmt.Errorf("no local AID — a2al register first")
	case 1:
		return aids[0], nil
	default:
		return "", fmt.Errorf("multiple local AIDs; pass --aid\n  %s", strings.Join(aids, "\n  "))
	}
}

func daemonAPIHostPorts(c *Client) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		hp, err := canonicalHostPort(raw)
		if err != nil || seen[hp] {
			return
		}
		seen[hp] = true
		out = append(out, hp)
	}
	add(c.Base)
	var cfg map[string]any
	if _, _, err := c.DoRequest(http.MethodGet, "/config", nil, &cfg); err == nil {
		if s, ok := cfg["api_addr"].(string); ok {
			add(s)
		}
	}
	return out
}

func serviceTCPDialAddr(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errNeedAddr
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if strings.Contains(s, "/") {
		return "", errServiceTCPPath
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return "", fmt.Errorf("invalid --addr %q: want host:port", raw)
	}
	return s, nil
}

func canonicalHostPort(raw string) (string, error) {
	s, err := serviceTCPDialAddr(raw)
	if err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	h := strings.Trim(host, "[]")
	switch strings.ToLower(h) {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0", "::":
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, port), nil
}

func probeServiceTCP(dialAddr string, d time.Duration) error {
	conn, err := net.DialTimeout("tcp", dialAddr, d)
	if err != nil {
		return fmt.Errorf("nothing listens at %s — start the HTTP service first, then retry", dialAddr)
	}
	_ = conn.Close()
	return nil
}

func inboundURLs(daemonBase, aid string) (root, v1 string) {
	base := strings.TrimRight(daemonBase, "/")
	root = base + "/aid/" + aid + "/"
	v1 = base + "/aid/" + aid + "/v1"
	return
}

func inboundShareText(aid, daemonBase string) string {
	root, v1 := inboundURLs(daemonBase, aid)
	return fmt.Sprintf(`Give this to other agents (they need a2ald on their machine):

  AID: %s
  Fetch: a2al_fetch to this AID; they add their own HTTP path (for example /v1/chat/completions or /hooks/agent).
  AID URL on their machine: http://127.0.0.1:<their-api>/aid/%s/<path>
  Local check on this machine: %s
  Chat-shaped local example: %s
  If they cannot reach you now and can wait: a2al_mailbox_send — that is not an HTTP reply.
  Long-lived TCP/WebSocket: a2al_tunnel_open, not one fetch.

This daemon does not invent your API. Fill in the path you actually serve.
Keep a2ald running. If other machines must find this AID, publish it.`, aid, aid, root, v1)
}
