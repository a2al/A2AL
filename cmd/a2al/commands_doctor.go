// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	statePass = "PASS"
	stateFail = "FAIL"
	stateWarn = "WARN"
	stateInfo = "INFO"
)

// Check is one doctor line. Name prefixes are stable so tests can match them.
// Hint is for the operator/agent deciding what to do next — only locally
// observed facts, or how to verify when the fact is not local. Guessed
// diagnoses do not belong here: doctor is treated as authority.
// Detail is ops/debug only (shown in --json, not in the default listing).
type Check struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Hint   string `json:"hint,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type netKind int

const (
	netPublic netKind = iota
	netLocal
	netPrivate
	netUnknown
)

func (k netKind) String() string {
	switch k {
	case netLocal:
		return "local"
	case netPrivate:
		return "private"
	case netUnknown:
		return "unknown"
	default:
		return "public"
	}
}

func cmdDoctor(c *Client, g globalOpts, args []string) {
	if len(args) != 0 {
		fatalf("usage: a2al doctor")
	}
	checks := runDoctor(c)
	fail := false
	for _, ch := range checks {
		if ch.State == stateFail {
			fail = true
		}
	}
	if g.JSON {
		printJSON(true, map[string]any{"ok": !fail, "checks": checks})
	} else {
		for _, ch := range checks {
			if g.Quiet && ch.State != stateFail {
				continue
			}
			fmt.Printf("%-4s  %s\n", ch.State, ch.Name)
			if ch.Hint != "" && ch.State != statePass {
				fmt.Printf("      %s\n", ch.Hint)
			}
		}
	}
	if fail {
		os.Exit(1)
	}
}

func runDoctor(c *Client) []Check {
	probe := *c
	hc := *c.HTTP
	if hc.Timeout == 0 || hc.Timeout > 3*time.Second {
		hc.Timeout = 3 * time.Second
	}
	probe.HTTP = &hc

	var st map[string]any
	if _, _, err := probe.DoRequest(http.MethodGet, "/status", nil, &st); err != nil {
		return []Check{{
			Name:  "daemon",
			State: stateFail,
			Hint:  daemonDownHint(c.Base),
		}}
	}

	kind, apiAddr, listen, boots := inferTopology(c)
	dataDir := jsonString(st["data_dir"])
	checks := []Check{{
		Name:   "daemon",
		State:  statePass,
		Detail: c.Base,
	}, topologyCheck(kind, dataDir, apiAddr, listen, boots)}

	if mcpRouteUp(c) {
		checks = append(checks, Check{Name: "mcp endpoint", State: statePass})
	} else {
		checks = append(checks, Check{
			Name:  "mcp endpoint",
			State: stateFail,
			Hint:  "No HTTP response from /mcp/ on this address. Confirm --api is this daemon's api_addr (GET /config).",
		})
	}

	peers := jsonInt(st["dht_peers"])
	uptime := jsonInt(st["uptime_seconds"])
	ready := jsonBool(st["network_ready"])
	checks = append(checks, networkChecks(kind, peers, uptime, ready)...)

	var agWrap struct {
		Agents []map[string]any `json:"agents"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/agents", nil, &agWrap); err != nil {
		checks = append(checks, Check{
			Name:  "identity",
			State: stateFail,
			Hint:  "Could not list identities on this daemon.",
		})
		return checks
	}

	checks = append(checks, identityAndPublish(agWrap.Agents)...)
	checks = append(checks, persistenceCheck(kind, jsonBool(st["persistent_service"]), jsonInt(st["endpoint_ttl_s"]), agWrap.Agents))
	checks = append(checks, inboundCheck(agWrap.Agents))
	if rc, ok := roomsCheck(c, agWrap.Agents); ok {
		checks = append(checks, rc)
	}
	return checks
}

func daemonDownHint(api string) string {
	return fmt.Sprintf("No daemon at %s. Start a2ald, or if you already started another copy, run: a2al doctor --api <that-url>", api)
}

func inferTopology(c *Client) (netKind, string, string, []string) {
	var cfg struct {
		Bootstrap  []string `json:"bootstrap"`
		APIAddr    string   `json:"api_addr"`
		ListenAddr string   `json:"listen_addr"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/config", nil, &cfg); err != nil {
		return netUnknown, "", "", nil
	}
	kind := netPublic
	if len(cfg.Bootstrap) > 0 {
		if allLoopback(cfg.Bootstrap) {
			kind = netLocal
		} else {
			kind = netPrivate
		}
	}
	return kind, cfg.APIAddr, cfg.ListenAddr, cfg.Bootstrap
}

func topologyCheck(kind netKind, dataDir, apiAddr, listen string, boots []string) Check {
	c := Check{Name: "topology", State: stateInfo}
	switch kind {
	case netUnknown:
		c.Hint = "Could not read /config; intended network is unknown. Do not assume public. Inspect GET /config: empty bootstrap = public, loopback = this machine, other = private cluster."
	case netLocal:
		c.Hint = "Configured local-only (loopback bootstrap)."
	case netPrivate:
		c.Hint = "Configured as a private cluster (non-loopback bootstrap), not the public DNS list."
	default:
		c.Hint = "Configured for the public network (empty bootstrap)."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mode=%s", kind)
	if dataDir != "" {
		fmt.Fprintf(&b, " data_dir=%s", dataDir)
	}
	if apiAddr != "" {
		fmt.Fprintf(&b, " api_addr=%s", apiAddr)
	}
	if listen != "" {
		fmt.Fprintf(&b, " listen=%s", listen)
	}
	if len(boots) > 0 {
		fmt.Fprintf(&b, " bootstrap=%s", strings.Join(boots, ","))
	}
	c.Detail = b.String()
	return c
}

func networkChecks(kind netKind, peers, uptime int, ready bool) []Check {
	// Routing-table size and network_ready are local signals. Doctor must not
	// turn them into join/findability verdicts.
	detail := fmt.Sprintf("dht_peers=%d uptime_s=%d network_ready=%v", peers, uptime, ready)
	table := "This node's routing table has no other nodes."
	if peers > 0 {
		table = "This node's routing table has other nodes."
	}
	verify := "To see whether lookup works, try resolve/fetch of a known AID. Do not wait for a peer count here."

	var hint string
	switch kind {
	case netUnknown:
		hint = "Intended network unknown (no /config). " + table + " " + verify
	case netLocal:
		hint = "Bootstrap is loopback: configured local-only. " + table + " Agents on this same daemon do not use that table."
	case netPrivate:
		hint = "Bootstrap is set (private cluster). " + table
		if peers == 0 {
			hint += " If this node should join a seed, try reaching that bootstrap address from here; if this node is the seed, an empty table is expected until others join."
		} else {
			hint += " Local view only — not proof the cluster is complete. " + verify
		}
	default:
		hint = "Bootstrap is empty: configured for the public network. " + table + " " + verify
		if uptime > 0 && uptime < 45 {
			hint = fmt.Sprintf("Bootstrap is empty: public network. Uptime %ds. ", uptime) + table + " " + verify
		}
	}
	return []Check{{Name: "network", State: stateInfo, Hint: hint, Detail: detail}}
}

func identityAndPublish(agents []map[string]any) []Check {
	if len(agents) == 0 {
		return []Check{{
			Name:  "identity",
			State: stateInfo,
			Hint:  "No agent identity yet. Create one in the Web UI, or: a2al register. Publish only if other machines must find you.",
		}}
	}
	out := []Check{{Name: "identity", State: statePass, Hint: fmt.Sprintf("%d agent AID(s)", len(agents))}}
	published := 0
	for _, a := range agents {
		if jsonBool(a["published_to_dht"]) {
			published++
		}
	}
	if published == 0 {
		out = append(out, Check{
			Name:  "publish",
			State: stateInfo,
			Hint:  "No local publish record on this daemon. That is not a lookup from another node, and does not prove the AID is unpublished elsewhere. Publish here only if other machines must find this node: a2al publish / a2al_agent_publish.",
		})
		return out
	}
	out = append(out, Check{
		Name:  "publish",
		State: stateInfo,
		Hint:  fmt.Sprintf("Local publish record for %d/%d identities on this daemon. Not a lookup from another node.", published, len(agents)),
	})
	return out
}

func persistenceCheck(kind netKind, persistent bool, ttl int, agents []map[string]any) Check {
	if persistent {
		return Check{Name: "persistence", State: statePass}
	}
	published := false
	for _, a := range agents {
		if jsonBool(a["published_to_dht"]) {
			published = true
			break
		}
	}
	if published && kind != netLocal && kind != netUnknown {
		hint := "Not a background service, so this process will not republish after it exits."
		if ttl > 0 {
			hint += fmt.Sprintf(" Record TTL on this daemon is %ds (not remaining time after exit).", ttl)
		}
		hint += " Keep it running, or: a2ald service install -user"
		return Check{Name: "persistence", State: stateWarn, Hint: hint}
	}
	return Check{
		Name:  "persistence",
		State: stateInfo,
		Hint:  "Not a background service. Fine for this session. Install a service only if this identity must keep republishing after logout.",
	}
}

func inboundCheck(agents []map[string]any) Check {
	var dead, live int
	for _, a := range agents {
		addr := strings.TrimSpace(jsonString(a["service_tcp"]))
		if addr == "" {
			continue
		}
		if tcpAlive(addr) {
			live++
		} else {
			dead++
		}
	}
	switch {
	case dead > 0:
		return Check{Name: "inbound", State: stateWarn, Hint: "Registered service_tcp does not accept TCP from this machine."}
	case live > 0:
		return Check{Name: "inbound", State: statePass}
	default:
		return Check{Name: "inbound", State: stateInfo, Hint: "No service_tcp registered on this daemon, so it has nothing to bridge inbound HTTP to. Outbound still works. Add one only if this agent should be callable."}
	}
}

func roomsCheck(c *Client, agents []map[string]any) (Check, bool) {
	if len(agents) == 0 {
		return Check{}, false
	}
	total, listed := 0, 0
	for _, a := range agents {
		aid := jsonString(a["aid"])
		if aid == "" {
			continue
		}
		var wrap struct {
			Groups []map[string]any `json:"groups"`
		}
		if _, _, err := c.DoRequest(http.MethodGet, "/agents/"+url.PathEscape(aid)+"/groups", nil, &wrap); err != nil {
			continue
		}
		listed++
		total += len(wrap.Groups)
	}
	if listed == 0 {
		return Check{
			Name:  "rooms",
			State: stateInfo,
			Hint:  "Could not list rooms. GET /agents/{AID}/groups on this daemon.",
		}, true
	}
	hint := fmt.Sprintf("%d room(s) listed on this daemon", total)
	if listed < len(agents) {
		hint += " (incomplete: some identities could not be listed)"
	}
	return Check{Name: "rooms", State: stateInfo, Hint: hint}, true
}

func mcpRouteUp(c *Client) bool {
	req, err := http.NewRequest(http.MethodGet, c.Base+"/mcp/", nil)
	if err != nil {
		return false
	}
	c.authHeader(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func tcpAlive(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func allLoopback(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		host := a
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "localhost" {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func jsonString(v any) string {
	s, _ := v.(string)
	return s
}

func jsonBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func jsonInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case float32:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
