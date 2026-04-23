// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo5-marketplace: end-to-end QUIC tunnel + HTTP to a remote service.
//
// Seller exposes a Q&A HTTP service (reason.qa). Buyer discovers Seller on the A2AL network
// and calls /ask over a QUIC tunnel without knowing Seller’s IP.
//
// vs demo4:
//   demo4 — async DHT mailbox (like mail)
//   demo5 — QUIC tunnel + synchronous HTTP (like a phone call)
//
// Start Buyer after Seller prints that it is online. Pre-built binary: demo5-marketplace from the demos-latest release (see doc/examples.md).
//
// Recommended — two machines, each with a2ald:
//
//	Machine A: a2ald  +  demo5-marketplace --role seller
//	Machine B: a2ald  +  demo5-marketplace --role buyer
//
// Single machine — QUIC needs two daemons (four terminals):
//
//	Seller a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
//	Buyer  a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
//	               --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
//	Seller demo:   demo5-marketplace --role seller
//	Buyer  demo:   demo5-marketplace --role buyer --api 127.0.0.1:2122
//
// Build from source (Go 1.22+): replace "demo5-marketplace" with "go run ." inside examples/demo5-marketplace/.
//
// LAN/offline: set --fallback-host to this host's LAN IP; Buyer adds --bootstrap <peer-ip>:4121.
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
//   --role  seller|buyer  role (required)
//   --api   HOST:PORT     REST address of local a2ald (default 127.0.0.1:2121)
//   --token TOKEN        a2ald api_token (if the daemon enables authentication)
//   --id    FILE          identity file path (default identity-<role>-<port>.json)
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
			fmt.Printf("  Loaded identity %s\n", path)
			return &id, nil
		}
	}
	fmt.Print("  Generating identity...")
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
	fmt.Printf(" OK\n  saved to %s\n", path)
	return id, nil
}

// ─── Agent setup ─────────────────────────────────────────────────────────────

func setupAgent(c *client, id *savedIdentity, serviceTCP string) error {
	fmt.Print("  Registering agent...")
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
			fmt.Println(" already exists; updated")
		} else {
			return fmt.Errorf("register: %w", err)
		}
	} else {
		fmt.Println(" OK")
	}

	fmt.Print("  Publishing endpoint to A2AL...")
	if err := c.do("POST", "/agents/"+id.AID+"/publish", struct{}{}, nil); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	fmt.Println(" OK")
	return nil
}

// ─── Gateway AID header ──────────────────────────────────────────────────────
//
// a2ald gateway prepends a 21-byte binary Remote AID to every inbound TCP
// connection before bridging the QUIC stream. A plain http.Serve would try to
// parse these bytes as an HTTP request and fail. aidListener reads the header
// in Accept() and exposes the AID via ConnContext so HTTP handlers can retrieve
// it from the request context.

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

// ─── Seller ──────────────────────────────────────────────────────────────────

// answers maps questions to canned answers for demo purposes.
var answers = map[string]string{
	"what is a2al":      "A2AL is a decentralized agent communication protocol. Agents find each other by identity (AID), not by IP address.",
	"how does a2al work": "A2AL uses a Kademlia DHT for peer discovery and QUIC tunnels for direct agent-to-agent communication, with Ed25519-based identity.",
	"what is an aid":    "An AID (Agent Identity) is a 21-byte address derived from an Ed25519 public key, similar to an Ethereum address but for AI agents.",
	"who made a2al":     "A2AL is an open protocol for decentralized AI agent communication and service discovery.",
}

func startSellerHTTP() (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("HTTP listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	svcAddr := fmt.Sprintf("127.0.0.1:%d", addr.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/ask", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Question string `json:"question"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q := strings.ToLower(strings.TrimSpace(req.Question))
		answer, ok := answers[q]
		if !ok {
			answer = fmt.Sprintf("(no canned answer; echo) %s", req.Question)
		}
		// Remote AID is injected by aidListener via ConnContext — cryptographically
		// verified by the daemon's mutual-TLS QUIC handshake.
		callerAID, _ := r.Context().Value(remoteAIDKey{}).(string)
		callerLabel := shortAID(callerAID)
		if callerAID == "" {
			callerLabel = "(unknown)"
		}
		fmt.Printf("\n[Seller] request from %s\n", callerLabel)
		fmt.Printf("         question: %q\n", req.Question)
		fmt.Printf("[Seller] sending answer\n")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"answer": answer})
	})

	srv := &http.Server{
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if ac, ok := c.(*aidConn); ok {
				return context.WithValue(ctx, remoteAIDKey{}, ac.remoteAID)
			}
			return ctx
		},
	}
	go func() {
		if err := srv.Serve(&aidListener{ln}); err != nil && !strings.Contains(err.Error(), "use of closed") {
			fmt.Fprintf(os.Stderr, "[Seller] HTTP error: %v\n", err)
		}
	}()
	return ln, svcAddr
}

func runSeller(c *client, idPath string) {
	fmt.Println("\n=== QA Seller ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("identity init: %v", err)
	}
	fmt.Printf("  AID: %s\n", id.AID)

	ln, svcAddr := startSellerHTTP()
	defer ln.Close()
	fmt.Printf("  Local HTTP: %s\n", svcAddr)

	if err := setupAgent(c, id, svcAddr); err != nil {
		fatal("%v", err)
	}

	// Register service on DHT.
	fmt.Print(`  Registering service "reason.qa"...`)
	topicReq := map[string]any{
		"services":  []string{"reason.qa"},
		"name":      "QA Service",
		"protocols": []string{"http"},
		"tags":      []string{"qa", "a2al"},
		"brief":     "General Q&A service — ask anything about A2AL",
		"ttl":       3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/services", topicReq, nil); err != nil {
		fatal("register service: %v", err)
	}
	fmt.Println(" OK")

	fmt.Printf(`
✓ Seller online
  service: reason.qa
  AID:     %s

  Waiting for Buyer calls (Ctrl-C to quit)...
  In the Web UI Discover tab, search "reason.qa" to see this service.

`, id.AID)

	// Keep alive with periodic heartbeat.
	for {
		time.Sleep(30 * time.Second)
		_ = c.do("POST", "/agents/"+id.AID+"/heartbeat", struct{}{}, nil)
	}
}

// ─── Buyer ───────────────────────────────────────────────────────────────────

var questions = []string{
	"What is A2AL?",
	"How does A2AL work?",
	"What is an AID?",
}

// providerEntry holds discovered provider info for display and selection.
type providerEntry struct {
	AID   string
	Name  string
	Brief string
}

// pickProvider shows a numbered list and gives the user 5 seconds to pick.
// Returns (index, userSelected=true) for an explicit choice, or (0, false) for auto.
// A single entry skips the prompt entirely.
// Typing a non-numeric or out-of-range value stops the countdown and waits for a
// valid number before proceeding.
func pickProvider(entries []providerEntry) (int, bool) {
	if len(entries) == 1 {
		return 0, false
	}
	fmt.Printf("\n  Found %d providers:\n", len(entries))
	for i, e := range entries {
		brief := e.Brief
		if len(brief) > 48 {
			brief = brief[:46] + "…"
		}
		fmt.Printf("    [%d] %-22s  %s\n", i+1, e.Name, brief)
		fmt.Printf("        %s\n", shortAID(e.AID))
	}
	fmt.Println()
	fmt.Printf("  Enter a number to select, or press Enter. Auto-selecting #1 in 5 seconds.\n")
	fmt.Printf("  Select [1–%d]: ", len(entries))

	rd := bufio.NewReader(os.Stdin)
	inputCh := make(chan string, 1)
	go func() {
		line, _ := rd.ReadString('\n')
		inputCh <- strings.TrimSpace(line)
	}()

	select {
	case raw := <-inputCh:
		n, err := strconv.Atoi(raw)
		if err == nil && n >= 1 && n <= len(entries) {
			fmt.Printf("  → Selected: [%d] %s\n", n, entries[n-1].Name)
			return n - 1, true
		}
		// Invalid input — stop countdown, wait for a valid number.
		fmt.Printf("  Invalid selection — enter a number from 1 to %d: ", len(entries))
		for {
			line, _ := rd.ReadString('\n')
			line = strings.TrimSpace(line)
			n2, err2 := strconv.Atoi(line)
			if err2 == nil && n2 >= 1 && n2 <= len(entries) {
				fmt.Printf("  → Selected: [%d] %s\n", n2, entries[n2-1].Name)
				return n2 - 1, true
			}
			fmt.Printf("  Please enter 1–%d: ", len(entries))
		}
	case <-time.After(5 * time.Second):
	}
	fmt.Printf("  No input — auto-selecting #1: %s\n", entries[0].Name)
	return 0, false
}

func runBuyer(c *client, idPath string) {
	fmt.Println("\n=== QA Buyer ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("identity init: %v", err)
	}
	fmt.Printf("  AID: %s\n\n", id.AID)

	// Register buyer agent (needed to use as local_aid for connect).
	fmt.Print("  Registering agent (for QUIC identity)...")
	regReq := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
	}
	if err := c.do("POST", "/agents", regReq, nil); err != nil {
		if !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "conflict") {
			fatal("register buyer: %v", err)
		}
	}
	fmt.Println(" OK")

	// Discover sellers — collect all entries, retry until at least one is found.
	fmt.Print("  Discovering \"reason.qa\" on A2AL")
	var allEntries []providerEntry
	for attempt := 0; attempt < 20; attempt++ {
		if attempt > 0 {
			fmt.Print(".")
			time.Sleep(3 * time.Second)
		}
		var resp struct {
			Entries []struct {
				AID   string `json:"aid"`
				Name  string `json:"name"`
				Brief string `json:"brief"`
			} `json:"entries"`
		}
		if err := c.do("POST", "/discover", map[string]any{"services": []string{"reason.qa"}}, &resp); err == nil && len(resp.Entries) > 0 {
			for _, e := range resp.Entries {
				allEntries = append(allEntries, providerEntry{AID: e.AID, Name: e.Name, Brief: e.Brief})
			}
			break
		}
	}
	fmt.Println()

	if len(allEntries) == 0 {
		fatal("reason.qa not found.\nStart Seller first and wait until it prints that it is online, then run Buyer.")
	}

	if len(allEntries) == 1 {
		e := allEntries[0]
		fmt.Printf("\n  Found 1 provider: %s\n  %s  (%s)\n", e.Name, e.Brief, shortAID(e.AID))
	}

	chosen, userSelected := pickProvider(allEntries)

	// Establish QUIC tunnel — behaviour differs by selection mode.
	connectReq := map[string]any{"local_aid": id.AID}
	var tunnelBase string

	if userSelected {
		e := allEntries[chosen]
		fmt.Printf("\n  Step: establish QUIC tunnel → %s (%s)... ", e.Name, shortAID(e.AID))
		var connResp struct {
			Tunnel string `json:"tunnel"`
		}
		if err := c.do("POST", "/connect/"+e.AID, connectReq, &connResp); err != nil {
			fmt.Printf("✗\n\nerror: Step \"establish QUIC tunnel\" failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "  Possible causes:")
			fmt.Fprintln(os.Stderr, "    • Daemon not reachable — confirm your local a2ald is running and the")
			fmt.Fprintln(os.Stderr, "      provider's a2ald is also online.")
			fmt.Fprintln(os.Stderr, "    • Wrong provider — verify the AID matches the expected Seller:")
			fmt.Fprintf(os.Stderr,  "      discovered AID: %s\n", e.AID)
			os.Exit(1)
		}
		fmt.Printf("OK\n  tunnel: %s\n", connResp.Tunnel)
		tunnelBase = "http://" + connResp.Tunnel
	} else {
		for i := chosen; i < len(allEntries); i++ {
			e := allEntries[i]
			if len(allEntries) > 1 {
				fmt.Printf("\n  [%d/%d] Step: establish QUIC tunnel → %s (%s)... ",
					i+1, len(allEntries), e.Name, shortAID(e.AID))
			} else {
				fmt.Printf("\n  Step: establish QUIC tunnel → %s (%s)... ", e.Name, shortAID(e.AID))
			}
			var connResp struct {
				Tunnel string `json:"tunnel"`
			}
			if err := c.do("POST", "/connect/"+e.AID, connectReq, &connResp); err != nil {
				fmt.Printf("✗  %v\n", err)
				if i+1 < len(allEntries) {
					fmt.Printf("  → trying next provider...\n")
				}
				continue
			}
			fmt.Printf("OK\n  tunnel: %s\n", connResp.Tunnel)
			tunnelBase = "http://" + connResp.Tunnel
			break
		}
		if tunnelBase == "" {
			fmt.Fprintf(os.Stderr, "\nerror: All %d provider(s) failed at step \"establish QUIC tunnel\".\n", len(allEntries))
			fmt.Fprintln(os.Stderr, "  Possible causes:")
			fmt.Fprintln(os.Stderr, "    • Daemon not reachable — confirm your local a2ald is running and the")
			fmt.Fprintln(os.Stderr, "      provider's a2ald is also online.")
			fmt.Fprintln(os.Stderr, "    • Wrong providers — the discovered AIDs may not be the Seller you expect.")
			fmt.Fprintln(os.Stderr, "      Compare the AIDs above with your Seller's printed AID.")
			os.Exit(1)
		}
	}

	fmt.Printf("\n  ── calls ─────────────────────────────────\n\n")

	// Call /ask for each question via the tunnel.
	httpClient := &http.Client{Timeout: 15 * time.Second}
	for _, q := range questions {
		fmt.Printf("  Q: %q\n", q)

		body, _ := json.Marshal(map[string]string{
			"question": q,
		})
		resp, err := httpClient.Post(tunnelBase+"/ask", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("  ✗ request failed: %v\n\n", err)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result struct {
			Answer string `json:"answer"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			fmt.Printf("  ✗ bad JSON: %v\n\n", err)
			continue
		}
		fmt.Printf("  A: %s\n\n", result.Answer)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("  ── done ──────────────────────────────────")
	fmt.Printf(`
✓ Demo5 complete
  Flow:
    1. Identity (AID + delegation proof)
    2. Publish reason.qa to DHT
    3. Discover (no Seller IP needed)
    4. QUIC tunnel (Buyer AID)
    5. HTTP /ask over tunnel (sync; not mailbox)
    6. Seller sees caller AID

`)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func shortAID(aid string) string {
	if len(aid) <= 20 {
		return aid
	}
	return aid[:8] + "…" + aid[len(aid)-6:]
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nerror: "+format+"\n", args...)
	os.Exit(1)
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	role := ""
	apiAddr := "127.0.0.1:2121"
	token := ""
	idPath := ""

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
		case arg == "--id":
			idPath = next()
		case strings.HasPrefix(arg, "--id="):
			idPath = strings.TrimPrefix(arg, "--id=")
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			os.Exit(1)
		}
	}

	if role == "" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  demo5-marketplace --role seller  [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  demo5-marketplace --role buyer   [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  (build from source: go run . --role seller|buyer ...)")
		os.Exit(1)
	}
	if idPath == "" {
		port := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
		idPath = "identity-" + role + "-" + port + ".json"
	}

	c := newClient(apiAddr, token)
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach a2ald at %s: %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "Make sure a2ald is running. Download: https://github.com/a2al/a2al/releases")
		fmt.Fprintln(os.Stderr, "See doc/examples.md or https://github.com/a2al/a2al for setup instructions.")
		os.Exit(1)
	}

	switch role {
	case "seller":
		runSeller(c, idPath)
	case "buyer":
		runBuyer(c, idPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q; use seller or buyer\n", role)
		os.Exit(1)
	}
}
