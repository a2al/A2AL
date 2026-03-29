// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo5-marketplace: 通过 QUIC 隧道直连调用 HTTP 服务的端到端验证。
//
// 场景：Seller 提供一个问答服务（reason.qa），Buyer 通过 A2AL 网络
// 发现 Seller 并通过 QUIC 隧道直接调用其 HTTP 接口，无需知道对方 IP。
//
// 与 demo4 的核心区别：
//   demo4 — DHT Mailbox 异步通信（信件往来）
//   demo5 — QUIC 隧道 + HTTP 同步调用（直接打电话）
//
// 【单机运行（4 个终端）】
//
// connect API 需要两个独立的 daemon 节点（QUIC 直连是跨节点操作）。
//
//	Terminal 1 — Seller daemon:
//	  a2ald --data-dir ./tmp/seller --fallback-host 127.0.0.1
//
//	Terminal 2 — Buyer daemon（bootstrap 指向 Seller daemon）:
//	  a2ald --data-dir ./tmp/buyer --listen 127.0.0.1:4122 \
//	        --api-addr 127.0.0.1:2122 --fallback-host 127.0.0.1 \
//	        --bootstrap 127.0.0.1:4121
//
//	Terminal 3 — Seller（等 Terminal 1 启动后运行）:
//	  go run . --role seller
//
//	Terminal 4 — Buyer（等 Seller 打印「已上线」后运行）:
//	  go run . --role buyer --api 127.0.0.1:2122
//
// 【双机运行】
//
//	机器 A:  a2ald --fallback-host <公网IP-A>
//	         go run . --role seller
//
//	机器 B:  a2ald --fallback-host <公网IP-B> --bootstrap <公网IP-A>:4121
//	         go run . --role buyer
//
// 【参数】
//
//	--role  seller|buyer   角色（必填）
//	--api   HOST:PORT      本机 a2ald REST 地址（默认 127.0.0.1:2121）
//	--token TOKEN          a2ald api_token（若配置了鉴权则填写）
//	--id    FILE           身份文件路径（默认 identity-<role>-<port>.json）
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
			fmt.Printf("  已加载身份文件 %s\n", path)
			return &id, nil
		}
	}
	fmt.Print("  生成新身份...")
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
	fmt.Printf(" 已生成并保存到 %s\n", path)
	return id, nil
}

// ─── Agent setup ─────────────────────────────────────────────────────────────

func setupAgent(c *client, id *savedIdentity, serviceTCP string) error {
	fmt.Print("  注册 agent...")
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
			fmt.Println(" 已存在，已更新")
		} else {
			return fmt.Errorf("register: %w", err)
		}
	} else {
		fmt.Println(" OK")
	}

	fmt.Print("  发布端点到 A2AL 网络...")
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
		fatal("无法启动 HTTP 服务: %v", err)
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
			answer = fmt.Sprintf("(未收录问题，原样返回) %s", req.Question)
		}
		// Remote AID is injected by aidListener via ConnContext — cryptographically
		// verified by the daemon's mutual-TLS QUIC handshake.
		callerAID, _ := r.Context().Value(remoteAIDKey{}).(string)
		callerLabel := shortAID(callerAID)
		if callerAID == "" {
			callerLabel = "(未知)"
		}
		fmt.Printf("\n[Seller] 收到来自 %s 的请求\n", callerLabel)
		fmt.Printf("         问题: %q\n", req.Question)
		fmt.Printf("[Seller] 返回答案\n")

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
			fmt.Fprintf(os.Stderr, "[Seller] HTTP 服务错误: %v\n", err)
		}
	}()
	return ln, svcAddr
}

func runSeller(c *client, idPath string) {
	fmt.Println("\n=== QA Seller — 问答服务提供方 ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("身份初始化: %v", err)
	}
	fmt.Printf("  AID: %s\n", id.AID)

	ln, svcAddr := startSellerHTTP()
	defer ln.Close()
	fmt.Printf("  本地 HTTP 服务: %s\n", svcAddr)

	if err := setupAgent(c, id, svcAddr); err != nil {
		fatal("%v", err)
	}

	// Register service on DHT.
	fmt.Print(`  注册服务 "reason.qa" 到 A2AL 网络...`)
	topicReq := map[string]any{
		"services":  []string{"reason.qa"},
		"name":      "QA Service",
		"protocols": []string{"http"},
		"tags":      []string{"qa", "a2al"},
		"brief":     "General Q&A service — ask anything about A2AL",
		"ttl":       3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/services", topicReq, nil); err != nil {
		fatal("注册服务: %v", err)
	}
	fmt.Println(" OK")

	fmt.Printf(`
✓ Seller 已上线
  服务: reason.qa
  AID:  %s

  等待来自 Buyer 的直连调用（Ctrl-C 退出）...
  可在 Web UI 的 Discover 标签页搜索 "reason.qa" 查看本服务。

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

func runBuyer(c *client, idPath string) {
	fmt.Println("\n=== QA Buyer — 服务使用方 ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("身份初始化: %v", err)
	}
	fmt.Printf("  AID: %s\n\n", id.AID)

	// Register buyer agent (needed to use as local_aid for connect).
	fmt.Print("  注册 agent（用于 QUIC 身份验证）...")
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

	// Discover seller.
	fmt.Print("  搜索 A2AL 网络中的 \"reason.qa\" 服务")
	var sellerAID string
	var sellerName, sellerBrief string
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
			sellerAID = resp.Entries[0].AID
			sellerName = resp.Entries[0].Name
			sellerBrief = resp.Entries[0].Brief
			break
		}
	}
	fmt.Println()

	if sellerAID == "" {
		fatal("未找到 reason.qa 服务。\n请先启动 Seller 并等待其打印「已上线」后再运行 Buyer。")
	}

	fmt.Printf("\n  找到服务方:\n")
	fmt.Printf("    AID:   %s\n", sellerAID)
	fmt.Printf("    名称:  %s\n", sellerName)
	fmt.Printf("    描述:  %s\n", sellerBrief)

	// Establish QUIC tunnel.
	fmt.Printf("\n  建立 A2AL 直连隧道（身份: %s）...", shortAID(id.AID))
	var connResp struct {
		Tunnel string `json:"tunnel"`
	}
	connectReq := map[string]any{
		"local_aid": id.AID,
	}
	if err := c.do("POST", "/connect/"+sellerAID, connectReq, &connResp); err != nil {
		fatal("建立隧道失败: %v\n  请确认 Seller 仍在运行，且两个节点的 daemon 已互联。", err)
	}
	tunnelBase := "http://" + connResp.Tunnel
	fmt.Printf(" OK\n  隧道地址: %s\n", connResp.Tunnel)

	fmt.Printf("\n  ── 开始调用 ──────────────────────────────\n\n")

	// Call /ask for each question via the tunnel.
	httpClient := &http.Client{Timeout: 15 * time.Second}
	for _, q := range questions {
		fmt.Printf("  问: %q\n", q)

		body, _ := json.Marshal(map[string]string{
			"question": q,
		})
		resp, err := httpClient.Post(tunnelBase+"/ask", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("  ✗ 请求失败: %v\n\n", err)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result struct {
			Answer string `json:"answer"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			fmt.Printf("  ✗ 响应解析失败: %v\n\n", err)
			continue
		}
		fmt.Printf("  答: %s\n\n", result.Answer)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("  ── 完成 ──────────────────────────────────")
	fmt.Printf(`
✓ Demo5 验证完成
  验证链路:
    1. 身份生成（AID + 委托证明）
    2. 服务发布到 DHT（reason.qa）
    3. Discover 搜索（无需知道 Seller IP）
    4. QUIC 隧道建立（携带 Buyer AID 身份）
    5. HTTP 直连调用（同步 RPC，非异步 mailbox）
    6. Seller 可验证调用方身份

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
	fmt.Fprintf(os.Stderr, "\n错误: "+format+"\n", args...)
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
				fmt.Fprintf(os.Stderr, "参数 %s 缺少值\n", arg)
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
			fmt.Fprintf(os.Stderr, "未知参数: %s\n", arg)
			os.Exit(1)
		}
	}

	if role == "" {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  go run . --role seller  [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  go run . --role buyer   [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		os.Exit(1)
	}
	if idPath == "" {
		port := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
		idPath = "identity-" + role + "-" + port + ".json"
	}

	c := newClient(apiAddr, token)
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法连接到 a2ald (%s): %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "请先启动 a2ald，例如: a2ald --data-dir ./tmp/node --fallback-host 127.0.0.1")
		os.Exit(1)
	}

	switch role {
	case "seller":
		runSeller(c, idPath)
	case "buyer":
		runBuyer(c, idPath)
	default:
		fmt.Fprintf(os.Stderr, "未知角色 %q，请使用 seller 或 buyer\n", role)
		os.Exit(1)
	}
}
