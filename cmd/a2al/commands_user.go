// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/identity"
)

type identityChoice struct {
	Addr string
	Kind string
}

func listIdentities(c *Client) ([]identityChoice, error) {
	var st map[string]any
	if _, _, err := c.DoRequest(http.MethodGet, "/status", nil, &st); err != nil {
		return nil, err
	}
	node, _ := st["node_aid"].(string)
	var agWrap struct {
		Agents []struct {
			AID string `json:"aid"`
		} `json:"agents"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/agents", nil, &agWrap); err != nil {
		return nil, err
	}
	out := []identityChoice{{Addr: node, Kind: "node"}}
	for _, a := range agWrap.Agents {
		out = append(out, identityChoice{Addr: a.AID, Kind: "agent"})
	}
	return out, nil
}

func pickPublishAID(c *Client, flagAID string) (string, error) {
	ids, err := listIdentities(c)
	if err != nil {
		return "", err
	}
	if flagAID != "" {
		return flagAID, nil
	}
	if len(ids) == 1 {
		return ids[0].Addr, nil
	}
	var b strings.Builder
	b.WriteString("Multiple identities available. Specify --aid:\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "  %s  (%s)\n", id.Addr, id.Kind)
	}
	return "", fmt.Errorf("%s", strings.TrimSuffix(b.String(), "\n"))
}

func cmdStatus(c *Client, g globalOpts, args []string) {
	if len(args) != 0 {
		fatalf("usage: a2al status")
	}
	var st map[string]any
	if _, _, err := c.DoRequest(http.MethodGet, "/status", nil, &st); err != nil {
		fatal(err)
	}
	var agWrap struct {
		Agents []map[string]any `json:"agents"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/agents", nil, &agWrap); err != nil {
		fatal(err)
	}
	if g.JSON {
		out := map[string]any{"status": st, "agents": agWrap.Agents}
		printJSON(true, out)
		return
	}
	if g.Quiet {
		fmt.Println(st["node_aid"])
		return
	}
	node := st["node_aid"].(string)
	pub := st["node_published"].(bool)
	var last string
	if v, ok := st["node_last_publish_at"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			last = formatAgo(t)
		}
	}
	online := "online"
	if !pub {
		online = "not published"
	}
	if last != "" {
		fmt.Printf("Node:    %s  (%s, published %s)\n", node, online, last)
	} else {
		fmt.Printf("Node:    %s  (%s)\n", node, online)
	}
	fmt.Printf("Agents:  %d registered\n", len(agWrap.Agents))
	for _, a := range agWrap.Agents {
		aid, _ := a["aid"].(string)
		var lp string
		if v, ok := a["last_publish_at"].(string); ok && v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				lp = formatAgo(t)
			}
		}
		if lp != "" {
			fmt.Printf("  %s  (published %s)\n", aid, lp)
		} else {
			fmt.Printf("  %s\n", aid)
		}
	}
}

func cmdRegister(c *Client, g globalOpts, args []string) {
	var eth, noPub bool
	var serviceTCP, saveMaster, ethKey string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--ethereum":
			eth = true
		case a == "--no-publish":
			noPub = true
		case a == "--service-tcp" && i+1 < len(args):
			i++
			serviceTCP = args[i]
		case a == "--save-master" && i+1 < len(args):
			i++
			saveMaster = args[i]
		case a == "--eth-key" && i+1 < len(args):
			i++
			ethKey = args[i]
		case strings.HasPrefix(a, "--service-tcp="):
			serviceTCP = strings.TrimPrefix(a, "--service-tcp=")
		case strings.HasPrefix(a, "--save-master="):
			saveMaster = strings.TrimPrefix(a, "--save-master=")
		case strings.HasPrefix(a, "--eth-key="):
			ethKey = strings.TrimPrefix(a, "--eth-key=")
		default:
			fatalf("unknown flag: %s", a)
		}
	}
	if eth {
		registerEthereum(c, g, serviceTCP, ethKey, noPub, saveMaster)
		return
	}
	registerEd25519(c, g, serviceTCP, saveMaster, noPub)
}

func registerEd25519(c *Client, g globalOpts, serviceTCP, saveMaster string, noPub bool) {
	var gen struct {
		MasterPrivateKeyHex      string `json:"master_private_key_hex"`
		OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
		DelegationProofHex       string `json:"delegation_proof_hex"`
		AID                      string `json:"aid"`
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/identity/generate", map[string]any{}, &gen); err != nil {
		fatal(err)
	}
	if saveMaster != "" {
		if err := os.WriteFile(saveMaster, []byte(gen.MasterPrivateKeyHex+"\n"), 0o600); err != nil {
			fatal(err)
		}
	}
	regBody := map[string]any{
		"operational_private_key_hex": gen.OperationalPrivateKeyHex,
		"delegation_proof_hex":        gen.DelegationProofHex,
		"service_tcp":                 serviceTCP,
	}
	var reg struct {
		AID string `json:"aid"`
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/agents", regBody, &reg); err != nil {
		fatal(err)
	}
	if !noPub {
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+reg.AID+"/publish", map[string]any{}, new(map[string]any)); err != nil {
			fatal(err)
		}
	}
	ident := &agentIdentityFile{
		AID:                      reg.AID,
		OperationalPrivateKeyHex: gen.OperationalPrivateKeyHex,
		DelegationProofHex:       gen.DelegationProofHex,
		ServiceTCP:               serviceTCP,
	}
	if err := saveAgentIdentity(ident); err != nil {
		fmt.Fprintf(os.Stderr, "a2al: warning: could not save identity file: %v\n", err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"aid": reg.AID, "identity_generate": gen, "published": !noPub})
		return
	}
	if g.Quiet {
		fmt.Println(reg.AID)
		return
	}
	fmt.Println("Generating identity...  ✓")
	if serviceTCP != "" {
		fmt.Printf("Service TCP: %s\n", serviceTCP)
	}
	if !noPub {
		fmt.Println("Publishing to DHT...  ✓")
	}
	fmt.Println()
	fmt.Println("⚠  Save your master key (displayed once, daemon does not retain it):")
	fmt.Printf("   %s\n", gen.MasterPrivateKeyHex)
	fmt.Println()
	fmt.Printf("AID: %s  (registered", reg.AID)
	if !noPub {
		fmt.Print(" and published")
	}
	fmt.Println(")")
	if p, err := agentIdentityPath(reg.AID); err == nil {
		fmt.Printf("Identity saved: %s\n", p)
	}
}

func decodeHexFlexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

func registerEthereum(c *Client, g globalOpts, serviceTCP, ethKey string, noPub bool, _ string) {
	if ethKey != "" {
		issued := uint64(time.Now().Unix())
		var proof struct {
			AID                      string `json:"aid"`
			DelegationProofHex       string `json:"delegation_proof_hex"`
			OperationalPrivateKeyHex string `json:"operational_private_key_hex,omitempty"`
			Warning                  string `json:"warning,omitempty"`
		}
		body := map[string]any{
			"ethereum_private_key_hex": strings.TrimPrefix(strings.TrimSpace(ethKey), "0x"),
			"issued_at":                issued,
			"expires_at":               uint64(0),
			"scope":                    1,
		}
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/ethereum/proof", body, &proof); err != nil {
			fatal(err)
		}
		regBody := map[string]any{
			"operational_private_key_hex": proof.OperationalPrivateKeyHex,
			"delegation_proof_hex":        proof.DelegationProofHex,
			"service_tcp":                 serviceTCP,
		}
		var reg struct {
			AID string `json:"aid"`
		}
		if _, _, err := c.DoRequest(http.MethodPost, "/agents", regBody, &reg); err != nil {
			fatal(err)
		}
		if !noPub {
			if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+reg.AID+"/publish", map[string]any{}, new(map[string]any)); err != nil {
				fatal(err)
			}
		}
		ident := &agentIdentityFile{
			AID:                      reg.AID,
			OperationalPrivateKeyHex: proof.OperationalPrivateKeyHex,
			DelegationProofHex:       proof.DelegationProofHex,
			ServiceTCP:               serviceTCP,
		}
		if err := saveAgentIdentity(ident); err != nil {
			fmt.Fprintf(os.Stderr, "a2al: warning: could not save identity file: %v\n", err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"aid": reg.AID, "published": !noPub})
			return
		}
		if g.Quiet {
			fmt.Println(reg.AID)
			return
		}
		fmt.Printf("AID: %s  (registered", reg.AID)
		if !noPub {
			fmt.Print(" and published")
		}
		fmt.Println(")")
		if p, err := agentIdentityPath(reg.AID); err == nil {
			fmt.Printf("Identity saved: %s\n", p)
		}
		return
	}

	// Interactive: wallet sign
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Ethereum agent address (0x…): ")
	agentStr, _ := reader.ReadString('\n')
	agentStr = strings.TrimSpace(agentStr)
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		fatal(err)
	}
	seedHex := hex.EncodeToString(seed)
	issued := uint64(time.Now().Unix())
	var dm struct {
		Message string `json:"message"`
	}
	dmb := map[string]any{
		"operational_private_key_seed_hex": seedHex,
		"agent":                            agentStr,
		"issued_at":                        issued,
		"expires_at":                       uint64(0),
		"scope":                            uint8(1),
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/agents/ethereum/delegation-message", dmb, &dm); err != nil {
		fatal(err)
	}
	fmt.Println()
	fmt.Println("Sign this message with your Ethereum wallet (personal_sign), then paste signature (0x…):")
	fmt.Println(strings.Repeat("─", 48))
	fmt.Println(dm.Message)
	fmt.Println(strings.Repeat("─", 48))
	fmt.Print("Signature: ")
	sigStr, _ := reader.ReadString('\n')
	sigStr = strings.TrimSpace(sigStr)
	opPriv := ed25519.NewKeyFromSeed(seed)
	var reg struct {
		AID string `json:"aid"`
	}
	regBody := map[string]any{
		"agent":                            agentStr,
		"issued_at":                        issued,
		"expires_at":                       uint64(0),
		"scope":                            uint8(1),
		"eth_signature_hex":                sigStr,
		"service_tcp":                      serviceTCP,
		"operational_private_key_seed_hex": seedHex,
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/agents/ethereum/register", regBody, &reg); err != nil {
		fatal(err)
	}
	sig, err := decodeHexFlexible(sigStr)
	if err != nil {
		fatal(fmt.Errorf("bad signature hex: %w", err))
	}
	aid, err := a2al.ParseAddress(agentStr)
	if err != nil {
		fatal(err)
	}
	proof, err := identity.ImportBlockchainDelegation(sig, dm.Message, opPriv.Public().(ed25519.PublicKey), aid, issued, 0, 1)
	if err != nil {
		fatal(err)
	}
	proofRaw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		fatal(err)
	}
	if !noPub {
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+reg.AID+"/publish", map[string]any{}, new(map[string]any)); err != nil {
			fatal(err)
		}
	}
	ident := &agentIdentityFile{
		AID:                      reg.AID,
		OperationalPrivateKeyHex: hex.EncodeToString(opPriv),
		DelegationProofHex:       hex.EncodeToString(proofRaw),
		ServiceTCP:               serviceTCP,
	}
	if err := saveAgentIdentity(ident); err != nil {
		fmt.Fprintf(os.Stderr, "a2al: warning: could not save identity file: %v\n", err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"aid": reg.AID, "published": !noPub})
		return
	}
	if g.Quiet {
		fmt.Println(reg.AID)
		return
	}
	fmt.Printf("AID: %s  (registered", reg.AID)
	if !noPub {
		fmt.Print(" and published")
	}
	fmt.Println(")")
	if p, err := agentIdentityPath(reg.AID); err == nil {
		fmt.Printf("Identity saved: %s\n", p)
	}
}

func cmdPublish(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al publish <service> [flags]  (e.g. lang.translate, gen.image)")
	}
	topic := args[0]
	var from, name, brief, cardURL, flagAID string
	var ttl uint64 = 3600
	var protos, tags []string
	skipConfirm := false
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--from" && i+1 < len(rest):
			i++
			from = rest[i]
		case a == "--name" && i+1 < len(rest):
			i++
			name = rest[i]
		case a == "--brief" && i+1 < len(rest):
			i++
			brief = rest[i]
		case a == "--url" && i+1 < len(rest):
			i++
			cardURL = rest[i]
		case a == "--aid" && i+1 < len(rest):
			i++
			flagAID = rest[i]
		case a == "--ttl" && i+1 < len(rest):
			i++
			v, err := strconv.ParseUint(rest[i], 10, 32)
			if err != nil {
				fatalf("bad --ttl: %v", err)
			}
			ttl = v
		case a == "--protocol" && i+1 < len(rest):
			i++
			protos = append(protos, rest[i])
		case a == "--tag" && i+1 < len(rest):
			i++
			tags = append(tags, rest[i])
		case a == "-y" || a == "--yes":
			skipConfirm = true
		default:
			fatalf("unknown flag: %s", a)
		}
	}
	aid, err := pickPublishAID(c, flagAID)
	if err != nil {
		fatal(err)
	}
	var draft *topicDraft
	if from != "" {
		var src string
		var err error
		draft, src, err = fetchAgentCardDraft(from)
		if err != nil {
			fatal(err)
		}
		if !g.Quiet && !g.JSON {
			fmt.Printf("Fetching agent card (%s)...\n", src)
		}
	}
	if draft == nil {
		draft = &topicDraft{}
	}
	if name != "" {
		draft.Name = name
	}
	if brief != "" {
		draft.Brief = brief
	}
	if cardURL != "" {
		draft.URL = cardURL
	}
	if len(protos) > 0 {
		draft.Protocols = protos
	}
	if len(tags) > 0 {
		draft.Tags = tags
	}
	if draft.Name == "" && draft.Brief == "" && len(draft.Protocols) == 0 && from == "" {
		// minimal wizard
		if !g.Quiet && !g.JSON && termTTY() {
			fmt.Print("Name (optional): ")
			draft.Name = readLineTrim()
			fmt.Print("Brief (optional): ")
			draft.Brief = readLineTrim()
			fmt.Print("Protocols (comma-separated, optional): ")
			if p := readLineTrim(); p != "" {
				for _, x := range strings.Split(p, ",") {
					draft.Protocols = append(draft.Protocols, strings.TrimSpace(x))
				}
			}
			fmt.Print("Public URL (optional): ")
			draft.URL = readLineTrim()
		}
	}
	meta := map[string]any{}
	if draft.URL != "" {
		meta["url"] = draft.URL
	}
	body := map[string]any{
		"services":  []string{topic},
		"name":      draft.Name,
		"protocols": draft.Protocols,
		"tags":      draft.Tags,
		"brief":     draft.Brief,
		"ttl":       ttl,
	}
	if len(meta) > 0 {
		body["meta"] = meta
	}
	if !skipConfirm && !g.JSON && !g.Quiet && termTTY() && from != "" {
		fmt.Printf("  name:       %s\n", draft.Name)
		fmt.Printf("  brief:      %s\n", draft.Brief)
		fmt.Printf("  protocols:  %s\n", strings.Join(draft.Protocols, ", "))
		fmt.Printf("  url:        %s\n", draft.URL)
		fmt.Print("Publish with these details? [Y/n]: ")
		if !promptYes(true) {
			fmt.Println("Cancelled.")
			return
		}
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+url.PathEscape(aid)+"/services", body, new(map[string]any)); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"ok": true, "aid": aid, "service": topic})
		return
	}
	if g.Quiet {
		return
	}
	fmt.Printf("Published service %q for %s.\n", topic, shortAID(aid))
}

func termTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func cmdUnpublish(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al unpublish <service> [--aid …]")
	}
	topic := args[0]
	flagAID := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--aid" && i+1 < len(args) {
			i++
			flagAID = args[i]
		} else {
			fatalf("unknown flag: %s", args[i])
		}
	}
	aid, err := pickPublishAID(c, flagAID)
	if err != nil {
		fatal(err)
	}
	p := "/agents/" + url.PathEscape(aid) + "/services/" + url.PathEscape(topic)
	if _, _, err := c.DoRequest(http.MethodDelete, p, map[string]any{}, new(map[string]any)); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"ok": true})
		return
	}
	if !g.Quiet {
		fmt.Printf("Removed service %q for %s. DHT record will expire within 1 hour.\n", topic, shortAID(aid))
	}
}

func cmdSearch(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al search <service> [<service>…] [--filter-protocol …] [--filter-tag …]  (e.g. lang.translate)")
	}
	var topics []string
	var fproto, ftags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--filter-protocol":
			if i+1 >= len(args) {
				fatalf("--filter-protocol needs a value")
			}
			i++
			fproto = append(fproto, args[i])
		case strings.HasPrefix(a, "--filter-protocol="):
			fproto = append(fproto, strings.TrimPrefix(a, "--filter-protocol="))
		case a == "--filter-tag":
			if i+1 >= len(args) {
				fatalf("--filter-tag needs a value")
			}
			i++
			ftags = append(ftags, args[i])
		case strings.HasPrefix(a, "--filter-tag="):
			ftags = append(ftags, strings.TrimPrefix(a, "--filter-tag="))
		case strings.HasPrefix(a, "--"):
			fatalf("unknown flag: %s", a)
		default:
			topics = append(topics, a)
		}
	}
	body := map[string]any{"services": topics}
	if len(fproto) > 0 || len(ftags) > 0 {
		body["filter"] = map[string]any{
			"protocols": fproto,
			"tags":      ftags,
		}
	}
	var out struct {
		Entries []map[string]any `json:"entries"`
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/discover", body, &out); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	if g.Quiet {
		for _, e := range out.Entries {
			fmt.Println(e["aid"])
		}
		return
	}
	fmt.Printf("Found %d agents:\n", len(out.Entries))
	hasCard := false
	for i, e := range out.Entries {
		if i > 0 {
			fmt.Println()
		}
		aid, _ := e["aid"].(string)
		name, _ := e["name"].(string)
		brief, _ := e["brief"].(string)
		var protos []string
		if p, ok := e["protocols"].([]any); ok {
			for _, x := range p {
				if s, ok := x.(string); ok {
					protos = append(protos, s)
				}
			}
		}
		var tags []string
		if t, ok := e["tags"].([]any); ok {
			for _, x := range t {
				if s, ok := x.(string); ok {
					tags = append(tags, s)
				}
			}
		}
		var metaURL string
		var metaExtra []string
		if meta, ok := e["meta"].(map[string]any); ok {
			if u, ok := meta["url"].(string); ok {
				metaURL = u
			}
			for k, v := range meta {
				if k == "url" {
					continue
				}
				metaExtra = append(metaExtra, fmt.Sprintf("%s=%v", k, v))
			}
		}
		fmt.Printf("  %s\n", aid)
		if name != "" {
			fmt.Printf("    name:      %s\n", name)
		}
		if len(protos) > 0 {
			fmt.Printf("    protocols: %s\n", strings.Join(protos, ", "))
		}
		if brief != "" {
			fmt.Printf("    brief:     %s\n", brief)
		}
		if metaURL != "" {
			fmt.Printf("    url:       %s\n", metaURL)
		}
		if len(tags) > 0 {
			fmt.Printf("    tags:      %s\n", strings.Join(tags, ", "))
		}
		for _, kv := range metaExtra {
			fmt.Printf("    meta:      %s\n", kv)
		}
		for _, p := range protos {
			if p == "a2a" || p == "mcp" {
				hasCard = true
			}
		}
	}
	if hasCard {
		fmt.Fprintln(os.Stderr, "\nTip: a2al info <aid>  — connect and fetch full agent card (a2a/mcp)")
	}
}

func cmdInfo(c *Client, g globalOpts, args []string) {
	if len(args) != 1 {
		fatalf("usage: a2al info <remote-aid>")
	}
	aid := args[0]
	var res map[string]any
	if _, _, err := c.DoRequest(http.MethodPost, "/resolve/"+aid, map[string]any{}, &res); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"resolve": res})
		return
	}
	if g.Quiet {
		fmt.Println(aid)
		return
	}
	fmt.Printf("AID:        %s\n", aid)
	if eps, ok := res["endpoints"].([]any); ok {
		var ss []string
		for _, x := range eps {
			if s, ok := x.(string); ok {
				ss = append(ss, s)
			}
		}
		fmt.Printf("Endpoints:  %s\n", strings.Join(ss, ", "))
	}
	if nt, ok := res["nat_type"]; ok && nt != nil {
		fmt.Printf("NAT:        %v\n", nt)
	}
	if seq, ok := res["seq"].(float64); ok {
		fmt.Printf("Seq:        %.0f\n", seq)
	}

	// Attempt to fetch agent card via tunnel. Output L1 info above first so
	// the user sees something immediately; the fetch may take a few seconds.
	fmt.Fprintln(os.Stderr, "\nFetching agent card... (Ctrl+C to skip)")
	card, src, err := tryFetchCardViaTunnel(c, aid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "(no agent card: %v)\n", err)
		return
	}
	fmt.Printf("\nAgent Card (%s):\n", src)
	if card.Name != "" {
		fmt.Printf("  name:      %s\n", card.Name)
	}
	if len(card.Protocols) > 0 {
		fmt.Printf("  protocols: %s\n", strings.Join(card.Protocols, ", "))
	}
	if card.Brief != "" {
		fmt.Printf("  brief:     %s\n", card.Brief)
	}
	if card.URL != "" {
		fmt.Printf("  url:       %s\n", card.URL)
	}
	if len(card.Tags) > 0 {
		fmt.Printf("  tags:      %s\n", strings.Join(card.Tags, ", "))
	}
}

// tryFetchCardViaTunnel establishes a QUIC tunnel to remoteAID and fetches
// /.well-known/agent.json (A2A) or /.well-known/mcp.json (MCP).
// Returns (nil, "", err) when no card is available.
func tryFetchCardViaTunnel(c *Client, remoteAID string) (*topicDraft, string, error) {
	var tun map[string]string
	if _, _, err := c.DoRequest(http.MethodPost, "/connect/"+remoteAID, map[string]any{}, &tun); err != nil {
		return nil, "", fmt.Errorf("connect: %w", err)
	}
	addr := tun["tunnel"]
	if addr == "" {
		return nil, "", fmt.Errorf("no tunnel address returned")
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	try := func(path string) ([]byte, error) {
		resp, err := hc.Get("http://" + addr + path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	if b, err := try("/.well-known/agent.json"); err == nil {
		if d, _, err := parseAgentCardJSON(b); err == nil {
			return d, "A2A Agent Card", nil
		}
	}
	if b, err := try("/.well-known/mcp.json"); err == nil {
		if d, _, err := parseAgentCardJSON(b); err == nil {
			return d, "MCP Server Card", nil
		}
	}
	return nil, "", fmt.Errorf("agent card not available")
}

func cmdGet(c *Client, g globalOpts, args []string) {
	if len(args) < 2 {
		fatalf("usage: a2al get <remote-aid> <path> [--header …] [--local-aid …]")
	}
	remote := args[0]
	path := args[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	localAID, rest := extractLocalAID(args[2:])
	headers := parseHeaders(rest)
	doHTTPThroughTunnel(c, g, http.MethodGet, remote, path, nil, headers, localAID)
}

func cmdPost(c *Client, g globalOpts, args []string) {
	if len(args) < 2 {
		fatalf("usage: a2al post <remote-aid> <path> [-d …] [--header …]")
	}
	remote := args[0]
	path := args[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var data string
	var hdrArgs []string
	for i := 2; i < len(args); i++ {
		a := args[i]
		if (a == "-d" || a == "--data") && i+1 < len(args) {
			i++
			data = args[i]
			continue
		}
		if strings.HasPrefix(a, "--data=") {
			data = strings.TrimPrefix(a, "--data=")
			continue
		}
		hdrArgs = append(hdrArgs, a)
	}
	body := strings.NewReader(data)
	if strings.HasPrefix(data, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(data, "@"))
		if err != nil {
			fatal(err)
		}
		body = strings.NewReader(string(b))
	}
	localAID, hdrArgs2 := extractLocalAID(hdrArgs)
	headers := parseHeaders(hdrArgs2)
	doHTTPThroughTunnel(c, g, http.MethodPost, remote, path, body, headers, localAID)
}

func parseHeaders(args []string) http.Header {
	h := make(http.Header)
	for i := 0; i < len(args); i++ {
		if args[i] == "--header" && i+1 < len(args) {
			i++
			k, v, ok := strings.Cut(args[i], ":")
			if ok {
				h.Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
	}
	return h
}

func extractLocalAID(args []string) (string, []string) {
	var localAID string
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--local-aid" && i+1 < len(args) {
			i++
			localAID = args[i]
		} else if strings.HasPrefix(args[i], "--local-aid=") {
			localAID = strings.TrimPrefix(args[i], "--local-aid=")
		} else {
			out = append(out, args[i])
		}
	}
	return localAID, out
}

func resolveLocalIdentityLabel(c *Client, localAID string) string {
	if localAID != "" {
		return shortAID(localAID) + " (agent)"
	}
	var st struct {
		NodeAID string `json:"node_aid"`
	}
	if _, _, err := c.DoRequest(http.MethodGet, "/status", nil, &st); err == nil && st.NodeAID != "" {
		return shortAID(st.NodeAID) + " (node)"
	}
	return "node (default)"
}

func doHTTPThroughTunnel(c *Client, g globalOpts, method, remoteAID, path string, body io.Reader, extra http.Header, localAID string) {
	connectBody := map[string]any{}
	if localAID != "" {
		connectBody["local_aid"] = localAID
	}
	if !g.Quiet && !g.JSON {
		label := resolveLocalIdentityLabel(c, localAID)
		fmt.Fprintf(os.Stderr, "Connecting as %s → %s\n", label, shortAID(remoteAID))
	}
	var tun map[string]string
	if _, _, err := c.DoRequest(http.MethodPost, "/connect/"+remoteAID, connectBody, &tun); err != nil {
		fatal(err)
	}
	addr := tun["tunnel"]
	if addr == "" {
		fatal(fmt.Errorf("no tunnel in response"))
	}
	url := "http://" + addr + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fatal(err)
	}
	for k, vv := range extra {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if method == http.MethodPost && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"status": resp.StatusCode, "body": string(b)})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "a2al: HTTP %s\n", resp.Status)
	}
	os.Stdout.Write(b)
	if len(b) > 0 && b[len(b)-1] != '\n' {
		fmt.Println()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
}
