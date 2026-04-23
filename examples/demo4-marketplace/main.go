// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo4-marketplace: Functional verification demo — encrypted notes, named service, and Sovereign Record.
//
// Alice is the translation provider; Bob is the client.
//
//   - Alice registers the named service "lang.translate", polls encrypted notes, and auto-replies.
//   - Bob discovers Alice by named service, sends a request via encrypted notes, and waits for the reply.
//
// Both talk only to local a2ald; P2P is handled by the daemon. Start Bob after Alice prints that she is online.
// Pre-built binary: demo4-marketplace from the demos-latest release (see doc/examples.md).
//
// Recommended — two machines, each running a2ald:
//
//	Machine A: a2ald  +  demo4-marketplace --role alice
//	Machine B: a2ald  +  demo4-marketplace --role bob
//
// Single machine — shared a2ald (demo4 only needs DHT encrypted notes / named service; both processes may share one daemon):
//
//	a2ald --fallback-host 127.0.0.1
//	demo4-marketplace --role alice   # terminal 2
//	demo4-marketplace --role bob     # terminal 3
//
// Single machine — two a2alds (four terminals; simulates cross-node P2P):
//
//	Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
//	Bob   a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
//	              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
//	Alice demo:   demo4-marketplace --role alice
//	Bob   demo:   demo4-marketplace --role bob --api 127.0.0.1:2122
//
// Build from source (Go 1.22+): replace "demo4-marketplace" with "go run ." inside examples/demo4-marketplace/.
//
// LAN/offline: set --fallback-host to this host's LAN IP; Bob adds --bootstrap <peer-ip>:4121.
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
//   --role  alice|bob    role (required)
//   --api   HOST:PORT    REST address of local a2ald (default 127.0.0.1:2121)
//   --token TOKEN        a2ald api_token (if the daemon enables authentication)
//   --id    FILE         identity file path (default identity-<role>-<port>.json)
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
			fmt.Printf("  Loaded identity %s\n  AID: %s\n", path, id.AID)
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
	fmt.Printf(" OK\n  AID: %s\n  Saved to %s\n", id.AID, path)
	return id, nil
}

// ─── TCP service shim ────────────────────────────────────────────────────────

// openDummyTCP opens a TCP listener solely to satisfy a2ald's service_tcp
// reachability check. This demo uses encrypted notes (mailbox API) for messaging (not QUIC streams),
// so the listener accepts and immediately closes connections.
func openDummyTCP() (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return ln, fmt.Sprintf("127.0.0.1:%d", addr.Port), nil
}

// ─── Agent setup ─────────────────────────────────────────────────────────────

func setupAgent(c *client, id *savedIdentity, serviceTCP string) error {
	fmt.Print("  Registering agent...")
	regReq := map[string]string{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
		"service_tcp":                 serviceTCP,
	}
	if err := c.do("POST", "/agents", regReq, nil); err != nil {
		if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "conflict") {
			patchReq := map[string]string{
				"operational_private_key_hex": id.OperationalPrivateKeyHex,
				"service_tcp":                 serviceTCP,
			}
			if err2 := c.do("PATCH", "/agents/"+id.AID, patchReq, nil); err2 != nil {
				return fmt.Errorf("patch service_tcp: %w", err2)
			}
			fmt.Println(" already exists; updated service_tcp")
		} else {
			return fmt.Errorf("register: %w", err)
		}
	} else {
		fmt.Println(" OK")
	}

	fmt.Print("  Publishing endpoint to Tangled...")
	if err := c.do("POST", "/agents/"+id.AID+"/publish", struct{}{}, nil); err != nil {
		return fmt.Errorf("publish endpoint: %w", err)
	}
	fmt.Println(" OK")
	return nil
}

// ─── Alice (provider) ────────────────────────────────────────────────────────

func runAlice(c *client, idPath string) {
	fmt.Println("\n=== Alice — translation provider ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("identity init: %v", err)
	}

	ln, svcTCP, err := openDummyTCP()
	if err != nil {
		fatal("TCP listen: %v", err)
	}
	defer ln.Close()

	if err := setupAgent(c, id, svcTCP); err != nil {
		fatal("%v", err)
	}

	// Publish Sovereign Record (rec_type=2): application-defined metadata.
	fmt.Print("  Publishing service metadata (Sovereign Record rec_type=2)...")
	svcMeta, _ := json.Marshal(map[string]any{
		"service": "translate",
		"pairs":   []string{"en→es", "es→en"},
		"price":   "free",
		"version": 1,
	})
	pubRecReq := map[string]any{
		"rec_type":       2,
		"payload_base64": base64.StdEncoding.EncodeToString(svcMeta),
		"ttl":            3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/records", pubRecReq, nil); err != nil {
		fmt.Printf(" warning (skipped): %v\n", err)
	} else {
		fmt.Println(" OK")
	}

	// Register named service (lang.translate).
	fmt.Print(`  Registering named service "lang.translate"...`)
	topicReq := map[string]any{
		"services":  []string{"lang.translate"},
		"name":      "Alice Translate",
		"protocols": []string{"mcp"},
		"tags":      []string{"en", "es"},
		"brief":     "English ↔ Spanish (toy) translation service",
		"ttl":       3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/services", topicReq, nil); err != nil {
		fatal("register service: %v", err)
	}
	fmt.Println(" OK")

	fmt.Printf("\n✓ Alice is online\n  AID: %s\n  Waiting for translation requests (Ctrl-C to quit)...\n\n", id.AID)

	// Poll inbox in a loop; auto-reply to every message.
	for {
		time.Sleep(3 * time.Second)

		var pollResp struct {
			Messages []struct {
				Sender     string `json:"sender"`
				MsgType    uint8  `json:"msg_type"`
				BodyBase64 string `json:"body_base64"`
			} `json:"messages"`
		}
		if err := c.do("POST", "/agents/"+id.AID+"/mailbox/poll", struct{}{}, &pollResp); err != nil {
			fmt.Printf("[Alice] poll error: %v\n", err)
			continue
		}
		for _, msg := range pollResp.Messages {
			body, _ := base64.StdEncoding.DecodeString(msg.BodyBase64)
			fmt.Printf("[Alice] message from %s: %q\n", shortAID(msg.Sender), string(body))

			reply := doTranslate(string(body))
			fmt.Printf("[Alice] auto-reply: %q\n\n", reply)

			sendReq := map[string]any{
				"recipient":   msg.Sender,
				"msg_type":    1,
				"body_base64": base64.StdEncoding.EncodeToString([]byte(reply)),
			}
			if err := c.do("POST", "/agents/"+id.AID+"/mailbox/send", sendReq, nil); err != nil {
				fmt.Printf("[Alice] reply failed: %v\n", err)
			}
		}
	}
}

// doTranslate simulates a translation service for demo purposes.
func doTranslate(req string) string {
	table := map[string]string{
		"hello":         "hola",
		"hello world":   "hola mundo",
		"good morning":  "buenos días",
		"good night":    "buenas noches",
		"thank you":     "gracias",
		"how are you":   "¿cómo estás?",
		"goodbye":       "adiós",
		"what is a2al":  "A2AL is a decentralized protocol for AI agent communication",
	}
	text := strings.TrimSpace(req)
	// Strip "translate:" prefix if present.
	if idx := strings.Index(strings.ToLower(text), "translate:"); idx >= 0 {
		text = strings.TrimSpace(text[idx+len("translate:"):])
	}
	if r, ok := table[strings.ToLower(text)]; ok {
		return r
	}
	return fmt.Sprintf("[translated] %s", text)
}

// ─── Bob (consumer) ──────────────────────────────────────────────────────────

// providerEntry holds discovered provider info for display and selection.
type providerEntry struct {
	AID   string
	Name  string
	Brief string
	Tags  []string
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
		if len(brief) > 45 {
			brief = brief[:43] + "…"
		}
		tagStr := ""
		if len(e.Tags) > 0 {
			tagStr = "  [" + strings.Join(e.Tags, ", ") + "]"
		}
		fmt.Printf("    [%d] %-22s  %s%s\n", i+1, e.Name, brief, tagStr)
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

// tryBobWithAlice performs the full mailbox round-trip: send message + wait up to
// 60s for a reply from aliceAID. Returns (reply, failedStep, err); failedStep is ""
// on success.
func tryBobWithAlice(c *client, bobAID, aliceAID string) (string, string, error) {
	// Optional: read Alice's Sovereign Record for service info.
	fmt.Printf("  Reading service record (rec_type=2)...")
	var recResp struct {
		Records []struct {
			PayloadBase64 string `json:"payload_base64"`
		} `json:"records"`
	}
	if err := c.do("GET", "/resolve/"+aliceAID+"/records?type=2", nil, &recResp); err != nil {
		fmt.Printf(" skipped\n")
	} else if len(recResp.Records) > 0 {
		payload, _ := base64.StdEncoding.DecodeString(recResp.Records[0].PayloadBase64)
		fmt.Printf(" %s\n", string(payload))
	} else {
		fmt.Println(" no records")
	}

	text := "translate: hello world"
	fmt.Printf("  Step: send mailbox message (%q)... ", text)
	sendReq := map[string]any{
		"recipient":   aliceAID,
		"msg_type":    1,
		"body_base64": base64.StdEncoding.EncodeToString([]byte(text)),
	}
	if err := c.do("POST", "/agents/"+bobAID+"/mailbox/send", sendReq, nil); err != nil {
		fmt.Printf("✗\n")
		return "", "send mailbox message", err
	}
	fmt.Printf("OK\n")

	fmt.Printf("  Step: wait for reply (up to 60s)")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		fmt.Print(".")
		var pollResp struct {
			Messages []struct {
				Sender     string `json:"sender"`
				MsgType    uint8  `json:"msg_type"`
				BodyBase64 string `json:"body_base64"`
			} `json:"messages"`
		}
		if err := c.do("POST", "/agents/"+bobAID+"/mailbox/poll", struct{}{}, &pollResp); err != nil {
			continue
		}
		for _, msg := range pollResp.Messages {
			if msg.Sender == aliceAID {
				body, _ := base64.StdEncoding.DecodeString(msg.BodyBase64)
				fmt.Println(" OK")
				return string(body), "", nil
			}
		}
	}
	fmt.Println()
	return "", "wait for reply", fmt.Errorf("timed out after 60s")
}

func printBobSuccess(reply string) {
	fmt.Printf("\n[Bob] translation result: %q\n", reply)
	fmt.Println("\n✓ demo4 verification complete")
	fmt.Println("  Flow: identity → Tangled publish → named service → discover → Sovereign Record → encrypted notes")
}

func runBob(c *client, idPath string) {
	fmt.Println("\n=== Bob — translation client ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("identity init: %v", err)
	}

	ln, svcTCP, err := openDummyTCP()
	if err != nil {
		fatal("TCP listen: %v", err)
	}
	defer ln.Close()

	if err := setupAgent(c, id, svcTCP); err != nil {
		fatal("%v", err)
	}

	// Discover translator by named service — collect all entries.
	fmt.Print(`  Discovering "lang.translate" (tag=es)`)
	discoverReq := map[string]any{
		"services": []string{"lang.translate"},
		"filter":   map[string]any{"tags": []string{"es"}},
	}
	var allEntries []providerEntry
	for attempt := 0; attempt < 15; attempt++ {
		if attempt > 0 {
			fmt.Print(".")
			time.Sleep(3 * time.Second)
		}
		var resp struct {
			Entries []struct {
				AID   string   `json:"aid"`
				Name  string   `json:"name"`
				Brief string   `json:"brief"`
				Tags  []string `json:"tags"`
			} `json:"entries"`
		}
		if err := c.do("POST", "/discover", discoverReq, &resp); err == nil && len(resp.Entries) > 0 {
			for _, e := range resp.Entries {
				allEntries = append(allEntries, providerEntry{AID: e.AID, Name: e.Name, Brief: e.Brief, Tags: e.Tags})
			}
			break
		}
	}
	fmt.Println()

	if len(allEntries) == 0 {
		fatal("no translation service found (lang.translate, tag: es).\nEnsure Alice is online and allow a few seconds for Tangled to sync.")
	}

	if len(allEntries) == 1 {
		e := allEntries[0]
		tagStr := ""
		if len(e.Tags) > 0 {
			tagStr = "  [" + strings.Join(e.Tags, ", ") + "]"
		}
		fmt.Printf("\n  Found 1 provider: %s%s\n  %s  (%s)\n", e.Name, tagStr, e.Brief, shortAID(e.AID))
	}

	chosen, userSelected := pickProvider(allEntries)

	if userSelected {
		e := allEntries[chosen]
		fmt.Printf("\n  Contacting: %s  (%s)\n", e.Name, shortAID(e.AID))
		reply, step, err := tryBobWithAlice(c, id.AID, e.AID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: Step %q failed: %v\n", step, err)
			fmt.Fprintln(os.Stderr, "  Possible causes:")
			fmt.Fprintln(os.Stderr, "    • Daemon not reachable — confirm your local a2ald is running and the")
			fmt.Fprintln(os.Stderr, "      provider's a2ald is also online.")
			fmt.Fprintln(os.Stderr, "    • Wrong provider — verify the AID matches the expected Alice:")
			fmt.Fprintf(os.Stderr,  "      discovered AID: %s\n", e.AID)
			os.Exit(1)
		}
		printBobSuccess(reply)
	} else {
		var reply string
		found := false
		for i := chosen; i < len(allEntries); i++ {
			e := allEntries[i]
			if len(allEntries) > 1 {
				fmt.Printf("\n  [%d/%d] Trying: %s  (%s)\n", i+1, len(allEntries), e.Name, shortAID(e.AID))
			} else {
				fmt.Printf("\n  Contacting: %s  (%s)\n", e.Name, shortAID(e.AID))
			}
			r, step, err := tryBobWithAlice(c, id.AID, e.AID)
			if err != nil {
				fmt.Printf("  ✗ Step %q failed: %v\n", step, err)
				if i+1 < len(allEntries) {
					fmt.Printf("  → trying next provider...\n")
				}
				continue
			}
			reply = r
			found = true
			break
		}
		if !found {
			fmt.Fprintf(os.Stderr, "\nerror: All %d provider(s) failed.\n", len(allEntries))
			fmt.Fprintln(os.Stderr, "  Possible causes:")
			fmt.Fprintln(os.Stderr, "    • Daemon not reachable — confirm your local a2ald is running and the")
			fmt.Fprintln(os.Stderr, "      provider's a2ald is also online.")
			fmt.Fprintln(os.Stderr, "    • Wrong providers — the discovered AIDs may not be the Alice you expect.")
			fmt.Fprintln(os.Stderr, "      Compare the AIDs above with your Alice's printed AID.")
			os.Exit(1)
		}
		printBobSuccess(reply)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func shortAID(aid string) string {
	if len(aid) <= 20 {
		return aid
	}
	return aid[:10] + "…" + aid[len(aid)-10:]
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
		fmt.Fprintln(os.Stderr, "  demo4-marketplace --role alice [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  demo4-marketplace --role bob   [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  (build from source: go run . --role alice|bob ...)")
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
	case "alice":
		runAlice(c, idPath)
	case "bob":
		runBob(c, idPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q; use alice or bob\n", role)
		os.Exit(1)
	}
}
