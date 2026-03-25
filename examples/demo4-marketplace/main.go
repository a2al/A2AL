// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// demo4-marketplace: Phase 4（Mailbox + Topic + Sovereign Record）功能验证 demo。
//
// 场景：Alice 是翻译服务提供方，Bob 是使用方。
//
//   - Alice 上线后发布 topic "ai/translate" 并持续 poll 收件箱，自动回复翻译请求。
//   - Bob 通过 topic discover 找到 Alice，通过 DHT mailbox 发送翻译请求，等待并显示结果。
//
// 二者都只和本机 a2ald 通信，P2P 通信由两个 daemon 完成。
//
// 【单机双实例测试】（四个终端）
//
//	Terminal 1 — Alice a2ald:
//	  a2ald --data-dir ./tmp/alice --listen :4121 --fallback-host 127.0.0.1
//
//	Terminal 2 — Bob a2ald（bootstrap 指向 Alice）:
//	  a2ald --data-dir ./tmp/bob --listen :4122 --api-addr 127.0.0.1:2122 \
//	        --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
//
//	Terminal 3 — Alice demo（先启动）:
//	  go run . --role alice
//
//	Terminal 4 — Bob demo（等 Alice 打印 "已上线" 后启动）:
//	  go run . --role bob --api 127.0.0.1:2122
//
// 【双机测试】
//
//	机器A：a2ald --fallback-host <公网IP-A>
//	       go run . --role alice
//
//	机器B：a2ald --fallback-host <公网IP-B> --bootstrap <公网IP-A>:4121
//	       go run . --role bob
//
// （两台机器默认 API 都是 127.0.0.1:2121，无需额外参数）
//
// 【参数】
//
//	--role alice|bob   角色（必填）
//	--api  HOST:PORT   本机 a2ald REST 地址（默认 127.0.0.1:2121）
//	--token TOKEN      a2ald api_token（若配置了鉴权则填写）
//	--id   FILE        身份文件路径（默认 identity-<role>-<port>.json）
package main

import (
	"bytes"
	"encoding/base64"
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
			fmt.Printf("  已加载身份文件 %s\n  AID: %s\n", path, id.AID)
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
	fmt.Printf(" OK\n  AID: %s\n  已保存到 %s\n", id.AID, path)
	return id, nil
}

// ─── TCP service shim ────────────────────────────────────────────────────────

// openDummyTCP opens a TCP listener solely to satisfy a2ald's service_tcp
// reachability check. This demo uses mailbox for messaging (not QUIC streams),
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
	fmt.Print("  注册 agent...")
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
			fmt.Println(" 已存在，已更新 service_tcp")
		} else {
			return fmt.Errorf("register: %w", err)
		}
	} else {
		fmt.Println(" OK")
	}

	fmt.Print("  发布端点到 DHT...")
	if err := c.do("POST", "/agents/"+id.AID+"/publish", struct{}{}, nil); err != nil {
		return fmt.Errorf("publish endpoint: %w", err)
	}
	fmt.Println(" OK")
	return nil
}

// ─── Alice (provider) ────────────────────────────────────────────────────────

func runAlice(c *client, idPath string) {
	fmt.Println("\n=== Alice — 翻译服务提供方 ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("身份初始化: %v", err)
	}

	ln, svcTCP, err := openDummyTCP()
	if err != nil {
		fatal("TCP 监听: %v", err)
	}
	defer ln.Close()

	if err := setupAgent(c, id, svcTCP); err != nil {
		fatal("%v", err)
	}

	// Publish sovereign service record (rec_type=2): application-defined metadata.
	fmt.Print("  发布服务元数据 (sovereign record rec_type=2)...")
	svcMeta, _ := json.Marshal(map[string]any{
		"service": "translate",
		"pairs":   []string{"en→zh", "zh→en"},
		"price":   "free",
		"version": 1,
	})
	pubRecReq := map[string]any{
		"rec_type":       2,
		"payload_base64": base64.StdEncoding.EncodeToString(svcMeta),
		"ttl":            3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/records", pubRecReq, nil); err != nil {
		fmt.Printf(" 警告（跳过）: %v\n", err)
	} else {
		fmt.Println(" OK")
	}

	// Register topic.
	fmt.Print(`  注册 topic "ai/translate"...`)
	topicReq := map[string]any{
		"topics":    []string{"ai/translate"},
		"name":      "Alice Translate",
		"protocols": []string{"mcp"},
		"tags":      []string{"en", "zh"},
		"brief":     "English ↔ Chinese translation service",
		"ttl":       3600,
	}
	if err := c.do("POST", "/agents/"+id.AID+"/topics", topicReq, nil); err != nil {
		fatal("注册 topic: %v", err)
	}
	fmt.Println(" OK")

	fmt.Printf("\n✓ Alice 已上线\n  AID: %s\n  等待翻译请求（Ctrl-C 退出）...\n\n", id.AID)

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
			fmt.Printf("[Alice] poll 错误: %v\n", err)
			continue
		}
		for _, msg := range pollResp.Messages {
			body, _ := base64.StdEncoding.DecodeString(msg.BodyBase64)
			fmt.Printf("[Alice] 收到来自 %s 的消息: %q\n", shortAID(msg.Sender), string(body))

			reply := doTranslate(string(body))
			fmt.Printf("[Alice] 自动回复: %q\n\n", reply)

			sendReq := map[string]any{
				"recipient":   msg.Sender,
				"msg_type":    1,
				"body_base64": base64.StdEncoding.EncodeToString([]byte(reply)),
			}
			if err := c.do("POST", "/agents/"+id.AID+"/mailbox/send", sendReq, nil); err != nil {
				fmt.Printf("[Alice] 回复失败: %v\n", err)
			}
		}
	}
}

// doTranslate simulates a translation service for demo purposes.
func doTranslate(req string) string {
	table := map[string]string{
		"hello":         "你好",
		"hello world":   "你好世界",
		"good morning":  "早上好",
		"good night":    "晚安",
		"thank you":     "谢谢",
		"how are you":   "你好吗",
		"goodbye":       "再见",
		"what is a2al":  "A2AL 是一个去中心化 AI Agent 通信协议",
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

func runBob(c *client, idPath string) {
	fmt.Println("\n=== Bob — 翻译服务使用方 ===")

	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("身份初始化: %v", err)
	}

	ln, svcTCP, err := openDummyTCP()
	if err != nil {
		fatal("TCP 监听: %v", err)
	}
	defer ln.Close()

	if err := setupAgent(c, id, svcTCP); err != nil {
		fatal("%v", err)
	}

	// Discover translator via topic.
	fmt.Print(`  discover "ai/translate" (tag=zh)`)
	discoverReq := map[string]any{
		"topics": []string{"ai/translate"},
		"filter": map[string]any{"tags": []string{"zh"}},
	}
	var discoverResp struct {
		Entries []struct {
			AID   string   `json:"aid"`
			Name  string   `json:"name"`
			Brief string   `json:"brief"`
			Tags  []string `json:"tags"`
		} `json:"entries"`
	}

	var aliceAID string
	for attempt := 0; attempt < 15; attempt++ {
		if attempt > 0 {
			fmt.Print(".")
			time.Sleep(3 * time.Second)
		}
		if err := c.do("POST", "/discover", discoverReq, &discoverResp); err != nil {
			continue
		}
		if len(discoverResp.Entries) > 0 {
			aliceAID = discoverResp.Entries[0].AID
			break
		}
	}
	fmt.Println()

	if aliceAID == "" {
		fatal("未找到翻译服务（topic: ai/translate, tag: zh）。\n请确认 Alice 已上线，且 DHT 已同步（通常需等待数秒）。")
	}

	fmt.Printf("\n  找到 %d 个翻译服务:\n", len(discoverResp.Entries))
	for _, e := range discoverResp.Entries {
		fmt.Printf("    %-20s  %s  tags=%v\n", shortAID(e.AID), e.Brief, e.Tags)
	}

	// Read Alice's sovereign record for extra service info.
	fmt.Printf("\n  读取 Alice 的服务元数据 (rec_type=2)...")
	var recResp struct {
		Records []struct {
			PayloadBase64 string `json:"payload_base64"`
		} `json:"records"`
	}
	if err := c.do("GET", "/resolve/"+aliceAID+"/records?type=2", nil, &recResp); err != nil {
		fmt.Printf(" 跳过 (%v)\n", err)
	} else if len(recResp.Records) > 0 {
		payload, _ := base64.StdEncoding.DecodeString(recResp.Records[0].PayloadBase64)
		fmt.Printf("\n  服务信息: %s\n", string(payload))
	} else {
		fmt.Println(" 暂无记录")
	}

	// Send mailbox message.
	text := "translate: hello world"
	fmt.Printf("\n[Bob] 发送翻译请求: %q\n", text)
	sendReq := map[string]any{
		"recipient":   aliceAID,
		"msg_type":    1,
		"body_base64": base64.StdEncoding.EncodeToString([]byte(text)),
	}
	if err := c.do("POST", "/agents/"+id.AID+"/mailbox/send", sendReq, nil); err != nil {
		fatal("发送失败: %v", err)
	}
	fmt.Println("[Bob] 请求已发送，等待翻译结果...")

	// Poll for Alice's reply.
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
		if err := c.do("POST", "/agents/"+id.AID+"/mailbox/poll", struct{}{}, &pollResp); err != nil {
			continue
		}
		for _, msg := range pollResp.Messages {
			if msg.Sender == aliceAID {
				body, _ := base64.StdEncoding.DecodeString(msg.BodyBase64)
				fmt.Printf("\n\n[Bob] 收到翻译结果: %q\n", string(body))
				fmt.Println("\n✓ Phase 4 功能验证完成！")
				fmt.Println("  验证链路：身份 → DHT端点发布 → Topic注册 → Discover → Sovereign记录 → Mailbox加密通信")
				return
			}
		}
	}
	fmt.Println("\n[Bob] 等待超时（60s），未收到 Alice 的回复。")
	fmt.Println("  请检查 Alice 是否仍在运行，以及两个 daemon 是否互相连通。")
	os.Exit(1)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func shortAID(aid string) string {
	if len(aid) <= 20 {
		return aid
	}
	return aid[:10] + "…" + aid[len(aid)-10:]
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
		fmt.Fprintln(os.Stderr, "  go run . --role alice [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  go run . --role bob   [--api 127.0.0.1:2121] [--id FILE] [--token TOKEN]")
		os.Exit(1)
	}
	if idPath == "" {
		port := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
		idPath = "identity-" + role + "-" + port + ".json"
	}

	c := newClient(apiAddr, token)
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法连接到 a2ald (%s): %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "请先启动 a2ald，例如: a2ald --data-dir ./tmp/alice --fallback-host 127.0.0.1")
		os.Exit(1)
	}

	switch role {
	case "alice":
		runAlice(c, idPath)
	case "bob":
		runBob(c, idPath)
	default:
		fmt.Fprintf(os.Stderr, "未知角色 %q，请使用 alice 或 bob\n", role)
		os.Exit(1)
	}
}
