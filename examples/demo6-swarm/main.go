// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo6-swarm: multi-agent “go-to-market” swarm demo.
//
// A company plans to sell overseas. Planner searches the Tangled network, discovers
// registered specialists, opens parallel QUIC tunnels, and merges answers into one report.
// Workers may go offline; Planner adapts to whatever is found.
//
// Start Planner after Worker prints that agents are online. Pre-built binary: demo6-swarm from the demos-latest release (see doc/examples.md).
//
// Recommended — two machines:
//
//	Worker machine:  a2ald  +  demo6-swarm --role worker
//	Planner machine: a2ald  +  demo6-swarm --role planner
//
// Single machine — four terminals:
//
//	Worker  a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
//	Planner a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
//	                --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
//	Worker  demo:   demo6-swarm --role worker
//	Planner demo:   demo6-swarm --role planner --api 127.0.0.1:2122
//
// Build from source (Go 1.22+): replace "demo6-swarm" with "go run ." inside examples/demo6-swarm/.
//
// LAN/offline: set --fallback-host to this host's LAN IP; Planner adds --bootstrap <worker-ip>:4121.
//
// a2ald parameters
// On the public internet, a2ald can be started with no extra flags. The following matter mainly
// for single-machine tests or when there is no public network access:
//
//   --fallback-host IP
//       Manually set the reachable IP written into endpoint records. On the public WAN, STUN/UPnP
//       discovery usually suffices without this. Use 127.0.0.1 on loopback, this host's LAN IP on a LAN,
//       or another reachable address when offline.
//
//   --bootstrap ip:port
//       Manually specify a seed peer to join the DHT. On the public internet, DNS resolves public
//       seeds automatically. Offline or on one machine: set to the peer (or first a2ald) at IP:4121.
//
//   --data-dir PATH
//       Data directory (identity, config, routing cache); default UserConfigDir/a2al.
//       Two a2ald instances on one machine must use different directories.
//
//   --listen ADDR
//       DHT UDP listen address; default :4121. A second instance needs another port (e.g. :4122).
//
//   --api-addr ADDR
//       REST API listen address; default 127.0.0.1:2121. A second instance needs another port
//       (e.g. 127.0.0.1:2122).
//
// demo parameters
//   --role   worker|planner  role (required)
//   --api    HOST:PORT       REST address of local a2ald (default 127.0.0.1:2121)
//   --token  TOKEN           a2ald api_token (if the daemon enables authentication)
//
// Web UI verification — in the Discover tab, search for these service names to see each agent:
//
//	reason.evaluate  /  data.search  /  reason.analyze  /  reason.recommend
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── REST client ─────────────────────────────────────────────────────────────

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(apiAddr, token string) *client {
	return &client{
		base:  "http://" + apiAddr,
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *client) do(method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ─── Identity ────────────────────────────────────────────────────────────────

type savedIdentity struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
}

func loadOrCreateIdentity(path string, c *client) (*savedIdentity, error) {
	if b, err := os.ReadFile(path); err == nil {
		var id savedIdentity
		if json.Unmarshal(b, &id) == nil && id.AID != "" {
			return &id, nil
		}
	}
	var resp struct {
		OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
		DelegationProofHex       string `json:"delegation_proof_hex"`
		AID                      string `json:"aid"`
	}
	if err := c.do("POST", "/identity/generate", struct{}{}, &resp); err != nil {
		return nil, fmt.Errorf("identity/generate: %w", err)
	}
	id := &savedIdentity{
		OperationalPrivateKeyHex: resp.OperationalPrivateKeyHex,
		DelegationProofHex:       resp.DelegationProofHex,
		AID:                      resp.AID,
	}
	b, _ := json.MarshalIndent(id, "", "  ")
	_ = os.WriteFile(path, b, 0o600)
	return id, nil
}

func setupAgent(c *client, id *savedIdentity, serviceTCP string) error {
	regReq := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
		"service_tcp":                 serviceTCP,
	}
	if err := c.do("POST", "/agents", regReq, nil); err != nil {
		if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "conflict") {
			patchReq := map[string]any{
				"operational_private_key_hex": id.OperationalPrivateKeyHex,
				"service_tcp":                 serviceTCP,
			}
			if err2 := c.do("PATCH", "/agents/"+id.AID, patchReq, nil); err2 != nil {
				return fmt.Errorf("patch agent: %w", err2)
			}
		} else {
			return fmt.Errorf("register: %w", err)
		}
	}
	return c.do("POST", "/agents/"+id.AID+"/publish", struct{}{}, nil)
}

// ─── Gateway AID header ──────────────────────────────────────────────────────
//
// a2ald gateway prepends a 21-byte binary Remote AID to every inbound TCP
// connection. aidListener reads it in Accept() so http.Serve gets clean HTTP.

type remoteAIDKey struct{}

type aidConn struct {
	net.Conn
	remoteAID string
}

type aidListener struct{ net.Listener }

func (l *aidListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		var hdr [21]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			conn.Close()
			continue
		}
		return &aidConn{Conn: conn, remoteAID: hex.EncodeToString(hdr[:])}, nil
	}
}

// ─── Expert definitions ───────────────────────────────────────────────────────

type expert struct {
	topic   string
	name    string
	brief   string
	tags    []string
	consult func(product, market string) string
}

func marketIsEU(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "eu") || strings.Contains(m, "europe")
}

func marketIsUS(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "us") || strings.Contains(m, "united states") ||
		strings.Contains(m, "north america")
}

var experts = []expert{
	{
		topic: "reason.evaluate",
		name:  "Compliance certification agent",
		brief: "Market-access compliance: standards and regulatory review",
		tags:  []string{"compliance", "certification", "regulation"},
		consult: func(product, market string) string {
			if marketIsEU(market) {
				return "CE/RED/WEEE + GDPR; typical lead time ~6–8 weeks"
			}
			if marketIsUS(market) {
				return "FCC/UL; Prop 65 / UN38.3 if battery; ~4–6 weeks"
			}
			return "Confirm target-market certification with local counsel"
		},
	},
	{
		topic: "data.search",
		name:  "Logistics agent",
		brief: "Cross-border shipping, routes, warehousing, last mile",
		tags:  []string{"logistics", "shipping", "supply-chain"},
		consult: func(product, market string) string {
			if marketIsEU(market) {
				return "Shenzhen→Rotterdam ~22d sea; DHL last mile; Rotterdam storage ~€0.8/unit/mo"
			}
			if marketIsUS(market) {
				return "Shenzhen→LA ~15d sea; FBA inbound; ocean ~$1.2/kg head haul"
			}
			return "Sea + local warehouse; confirm quotes at destination port"
		},
	},
	{
		topic: "reason.analyze",
		name:  "Tariffs & trade agent",
		brief: "HS codes, duties, customs paperwork",
		tags:  []string{"customs", "tariff", "trade"},
		consult: func(product, market string) string {
			if marketIsEU(market) {
				return "HS 8517.62; EU duty 0%; NL VAT 21%; EUR.1 + CE docs"
			}
			if marketIsUS(market) {
				return "HS 8517.62; US duty ~7.5% (301); FCC ID + origin declaration"
			}
			return "Confirm HS and duty with broker; commercial invoice + packing list"
		},
	},
	{
		topic: "reason.recommend",
		name:  "Localization agent",
		brief: "Pricing and localization fit for the target market",
		tags:  []string{"localization", "market-fit", "pricing"},
		consult: func(product, market string) string {
			if marketIsEU(market) {
				return "Peers ~€129–199; suggest €119; DE/FR/ES packs available"
			}
			if marketIsUS(market) {
				return "Peers ~$149–199; suggest $129; emphasize health tracking in US copy"
			}
			return "Benchmark local peers; adapt language and positioning"
		},
	},
}

func shortAID(aid string) string {
	if len(aid) <= 16 {
		return aid
	}
	return aid[:8] + "…" + aid[len(aid)-6:]
}

// ─── Worker ──────────────────────────────────────────────────────────────────

func runWorker(c *client, apiPort string) {
	fmt.Println("\n=== Registering agents ===")

	type agentInfo struct {
		id *savedIdentity
	}
	agents := make([]agentInfo, len(experts))

	for i, exp := range experts {
		expCopy := exp
		shortTopic := exp.topic
		idPath := fmt.Sprintf("identity-worker-%d-%s.json", i+1, apiPort)

		fmt.Printf("\n[%d/%d] %s\n", i+1, len(experts), exp.name)

		fmt.Print("  Generating identity...")
		id, err := loadOrCreateIdentity(idPath, c)
		if err != nil {
			fatal("identity init [%s]: %v", exp.name, err)
		}
		fmt.Printf(" AID: %s\n", shortAID(id.AID))

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatal("HTTP listen [%s]: %v", exp.name, err)
		}
		svcAddr := fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)

		fmt.Print("  Registering agent...")
		if err := setupAgent(c, id, svcAddr); err != nil {
			fatal("register [%s]: %v", exp.name, err)
		}
		fmt.Println(" OK")

		fmt.Printf("  Registering service %s...", shortTopic)
		topicReq := map[string]any{
			"services":  []string{exp.topic},
			"name":      exp.name,
			"protocols": []string{"http"},
			"tags":      exp.tags,
			"brief":     exp.brief,
			"ttl":       3600,
		}
		if err := c.do("POST", "/agents/"+id.AID+"/services", topicReq, nil); err != nil {
			fatal("register service [%s]: %v", exp.name, err)
		}
		fmt.Println(" OK")

		mux := http.NewServeMux()
		mux.HandleFunc("/consult", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				Product string `json:"product"`
				Market  string `json:"market"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			callerAID, _ := r.Context().Value(remoteAIDKey{}).(string)
			result := expCopy.consult(req.Product, req.Market)
			fmt.Printf("\n  [%s] consult from %s\n  → %s\n",
				expCopy.name, shortAID(callerAID), result)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": result})
		})

		srv := &http.Server{
			Handler: mux,
			ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				if ac, ok := conn.(*aidConn); ok {
					return context.WithValue(ctx, remoteAIDKey{}, ac.remoteAID)
				}
				return ctx
			},
		}
		go func() {
			if err := srv.Serve(&aidListener{ln}); err != nil &&
				!strings.Contains(err.Error(), "use of closed") {
				fmt.Fprintf(os.Stderr, "[%s] HTTP error: %v\n", expCopy.name, err)
			}
		}()

		fmt.Printf("  ✓ online\n")
		agents[i] = agentInfo{id: id}
	}

	fmt.Printf(`
Agents online — waiting (Ctrl-C to quit)
Web UI Discover tab: reason.evaluate / data.search / reason.analyze / reason.recommend

`)

	for {
		time.Sleep(30 * time.Second)
		for _, a := range agents {
			_ = c.do("POST", "/agents/"+a.id.AID+"/heartbeat", struct{}{}, nil)
		}
	}
}

// ─── Planner ─────────────────────────────────────────────────────────────────

type expertResult struct {
	topic  string
	name   string
	aid    string
	result string
	err    error
}

func runPlanner(c *client, apiPort string) {
	fmt.Println("\n=== Go-to-market — Planner ===")
	fmt.Println()

	idPath := fmt.Sprintf("identity-planner-%s.json", apiPort)
	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("identity init: %v", err)
	}
	fmt.Printf("  Planner AID: %s\n\n", shortAID(id.AID))

	regReq := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
	}
	if err := c.do("POST", "/agents", regReq, nil); err != nil {
		if !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "conflict") {
			fatal("register planner: %v", err)
		}
	}

	product := "smartwatch"
	market := "EU"
	fmt.Printf("  Task: %s → %s market\n\n", product, market)

	// Discover agents in parallel; print each as it's found.
	fmt.Println("  Searching Tangled...")
	type discovery struct {
		topic   string
		aid     string   // primary AID (Entries[0]) for display
		name    string
		allAIDs []string // all discovered AIDs, primary first
	}
	discoveryCh := make(chan discovery, len(experts))
	for _, exp := range experts {
		exp := exp
		go func() {
			var resp struct {
				Entries []struct {
					AID  string `json:"aid"`
					Name string `json:"name"`
				} `json:"entries"`
			}
			for attempt := 0; attempt < 10; attempt++ {
				if attempt > 0 {
					time.Sleep(2 * time.Second)
				}
			if err := c.do("POST", "/discover",
				map[string]any{"services": []string{exp.topic}}, &resp); err == nil &&
				len(resp.Entries) > 0 {
				allAIDs := make([]string, 0, len(resp.Entries))
				for _, e := range resp.Entries {
					allAIDs = append(allAIDs, e.AID)
				}
				discoveryCh <- discovery{exp.topic, resp.Entries[0].AID, resp.Entries[0].Name, allAIDs}
				return
			}
			}
			discoveryCh <- discovery{exp.topic, "", "", nil}
		}()
	}

	discovered := make([]discovery, 0, len(experts))
	for range experts {
		d := <-discoveryCh
		if d.aid != "" {
			fmt.Printf("  found: %-28s  %s  (%s)\n", d.name, shortAID(d.aid), d.topic)
			discovered = append(discovered, d)
		} else {
			fmt.Printf("  not found: %-24s  skip\n", d.topic)
		}
	}

	if len(discovered) == 0 {
		fatal("no agents found on the network.\nStart Worker first and wait until agents are online, then run Planner.")
	}

	fmt.Printf("\n  Building swarm (%d agents)\n", len(discovered))
	fmt.Println("  Running parallel consults...\n")

	// Connect + query all discovered experts in parallel.
	results := make(chan expertResult, len(discovered))
	var wg sync.WaitGroup
	for _, d := range discovered {
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			var connResp struct {
				Tunnel string `json:"tunnel"`
			}
			// Try each discovered candidate in order; fall back on tunnel failure.
			var tunnelAddr string
			for i, aid := range d.allAIDs {
				if err := c.do("POST", "/connect/"+aid,
					map[string]any{"local_aid": id.AID}, &connResp); err != nil {
					if i+1 < len(d.allAIDs) {
						fmt.Printf("  [%-18s] candidate %d/%d tunnel failed (%v); retrying…\n",
							d.name, i+1, len(d.allAIDs), err)
						continue
					}
					results <- expertResult{topic: d.topic, name: d.name, aid: aid,
						err: fmt.Errorf("tunnel: %w", err)}
					return
				}
				tunnelAddr = connResp.Tunnel
				if i > 0 {
					fmt.Printf("  [%-18s] fallback candidate %d/%d — tunnel OK\n",
						d.name, i+1, len(d.allAIDs))
				}
				break
			}

			hc := &http.Client{Timeout: 15 * time.Second}
			body, _ := json.Marshal(map[string]string{
				"product": product,
				"market":  market,
			})
			resp, err := hc.Post("http://"+tunnelAddr+"/consult",
				"application/json", bytes.NewReader(body))
			if err != nil {
				results <- expertResult{topic: d.topic, name: d.name, aid: d.aid,
					err: fmt.Errorf("HTTP call: %w", err)}
				return
			}
			defer resp.Body.Close()
			var out struct {
				Result string `json:"result"`
			}
			raw, _ := io.ReadAll(resp.Body)
			_ = json.Unmarshal(raw, &out)
			results <- expertResult{topic: d.topic, name: d.name, aid: d.aid, result: out.Result}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and print as they arrive.
	collected := make(map[string]expertResult)
	for r := range results {
		if r.err != nil {
			fmt.Printf("  [%-18s] ✗  %v\n", r.name, r.err)
		} else {
			fmt.Printf("  [%-18s] ✓  %s\n", r.name, r.result)
		}
		collected[r.topic] = r
	}

	// Final report.
	fmt.Printf(`
  ══════════════════════════════════
  Summary  %s → %s
  ══════════════════════════════════
`, product, market)

	labels := []struct{ topic, label string }{
		{"reason.evaluate", "Compliance"},
		{"data.search", "Logistics"},
		{"reason.analyze", "Tariffs"},
		{"reason.recommend", "Localization"},
	}
	for _, l := range labels {
		if r, ok := collected[l.topic]; ok && r.err == nil {
			fmt.Printf("  %-12s: %s\n", l.label, r.result)
		} else {
			fmt.Printf("  %-12s: (expert offline — no data)\n", l.label)
		}
	}

	fmt.Printf(`  ══════════════════════════════════

✓ Demo6 complete
  Flow:
    1. Register multiple agents (4 AIDs on Worker)
    2. Publish topics to DHT
    3. Planner parallel discover
    4. Open %d parallel QUIC tunnels (Planner identity)
    5. Concurrent HTTP-over-QUIC + gateway AID header
    6. Merge results into one report

`, len(discovered))
}

// ─── Main ────────────────────────────────────────────────────────────────────

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nerror: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	role := ""
	apiAddr := "127.0.0.1:2121"
	token := ""

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		next := func() string {
			i++
			if i >= len(os.Args) {
				fmt.Fprintf(os.Stderr, "missing value for %s\n", arg)
				os.Exit(1)
			}
			return os.Args[i]
		}
		switch {
		case arg == "--role":
			role = next()
		case strings.HasPrefix(arg, "--role="):
			role = strings.TrimPrefix(arg, "--role=")
		case arg == "--api":
			apiAddr = next()
		case strings.HasPrefix(arg, "--api="):
			apiAddr = strings.TrimPrefix(arg, "--api=")
		case arg == "--token":
			token = next()
		case strings.HasPrefix(arg, "--token="):
			token = strings.TrimPrefix(arg, "--token=")
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			os.Exit(1)
		}
	}

	if role == "" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  demo6-swarm --role worker   [--api 127.0.0.1:2121] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  demo6-swarm --role planner  [--api 127.0.0.1:2122] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  (build from source: go run . --role worker|planner ...)")
		os.Exit(1)
	}

	apiPort := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
	c := newClient(apiAddr, token)
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach a2ald at %s: %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "Make sure a2ald is running. Download: https://github.com/a2al/a2al/releases")
		fmt.Fprintln(os.Stderr, "See doc/examples.md or https://github.com/a2al/a2al for setup instructions.")
		os.Exit(1)
	}

	switch role {
	case "worker":
		runWorker(c, apiPort)
	case "planner":
		runPlanner(c, apiPort)
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q; use worker or planner\n", role)
		os.Exit(1)
	}
}
