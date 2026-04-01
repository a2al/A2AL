// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo6-swarm: 多 Agent 协作出海决策 Swarm。
//
// 场景：企业想将产品打入海外市场。Planner 搜索 Tangled 网络，动态发现已注册的
// 各领域 Agent，组建 Swarm，并行建立 QUIC 隧道咨询，汇总为出海方案。
// Agent 随时可下线，Planner 按实际发现情况动态处理，无需预先知道有多少个 Agent。
//
// 【单机运行（4 个终端）】
//
//	Terminal 1 — Worker daemon:
//	  a2ald --data-dir ./tmp/worker --fallback-host 127.0.0.1
//
//	Terminal 2 — Planner daemon（bootstrap 指向 Worker daemon）:
//	  a2ald --data-dir ./tmp/planner --listen 127.0.0.1:4122 \
//	        --api-addr 127.0.0.1:2122 --fallback-host 127.0.0.1 \
//	        --bootstrap 127.0.0.1:4121
//
//	Terminal 3 — Worker（等 Terminal 1 启动后运行）:
//	  go run . --role worker
//
//	Terminal 4 — Planner（等 Worker 打印「已上线」后运行）:
//	  go run . --role planner --api 127.0.0.1:2122
//
// 【Web UI 验证】在 Discover 标签页分别搜索以下服务名可看到对应 Agent：
//
//	reason.evaluate  /  data.search  /  reason.analyze  /  reason.recommend
//
// 【参数】
//
//	--role   worker|planner  角色（必填）
//	--api    HOST:PORT        本机 a2ald REST 地址（默认 127.0.0.1:2121）
//	--token  TOKEN            a2ald api_token（若配置了鉴权则填写）
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

var experts = []expert{
	{
		topic: "reason.evaluate",
		name:  "国际合规认证 Agent",
		brief: "产品准入合规评估，含认证标准与法规审查",
		tags:  []string{"compliance", "certification", "regulation"},
		consult: func(product, market string) string {
			if strings.Contains(market, "欧") {
				return "需 CE/RED/WEEE 认证，GDPR 隐私合规，认证周期约 6-8 周"
			}
			if strings.Contains(market, "美") || strings.Contains(market, "北美") {
				return "需 FCC/UL 认证，加州 Prop 65 若含电池需 UN38.3，周期约 4-6 周"
			}
			return "需目标市场准入认证，建议咨询当地合规机构"
		},
	},
	{
		topic: "data.search",
		name:  "供应链物流 Agent",
		brief: "跨境物流方案查询，含运输路线、仓储与末端配送",
		tags:  []string{"logistics", "shipping", "supply-chain"},
		consult: func(product, market string) string {
			if strings.Contains(market, "欧") {
				return "深圳→鹿特丹海运约 22 天，推荐 DHL 末端配送，鹿特丹仓储 €0.8/件/月"
			}
			if strings.Contains(market, "美") || strings.Contains(market, "北美") {
				return "深圳→洛杉矶海运约 15 天，亚马逊 FBA 入仓，头程海运 $1.2/kg"
			}
			return "建议海运+目的地本地仓，具体报价需目标港口确认"
		},
	},
	{
		topic: "reason.analyze",
		name:  "关税贸易 Agent",
		brief: "HS 编码与关税税率分析，含清关文件建议",
		tags:  []string{"customs", "tariff", "trade"},
		consult: func(product, market string) string {
			if strings.Contains(market, "欧") {
				return "HS 8517.62，欧盟关税 0%，荷兰 VAT 21%，需 EUR.1 产地证+CE 证书"
			}
			if strings.Contains(market, "美") || strings.Contains(market, "北美") {
				return "HS 8517.62，美国关税 7.5%（301 税），需 FCC ID + 原产地申报"
			}
			return "需确认 HS 编码和目标国税率，准备商业发票+装箱单"
		},
	},
	{
		topic: "reason.recommend",
		name:  "本地化市场 Agent",
		brief: "目标市场定价策略与本地化适配建议",
		tags:  []string{"localization", "market-fit", "pricing"},
		consult: func(product, market string) string {
			if strings.Contains(market, "欧") {
				return "主要竞品 Amazfit €129/Garmin €199，建议定价 €119，DE/FR/ES 语言包已覆盖"
			}
			if strings.Contains(market, "美") || strings.Contains(market, "北美") {
				return "主要竞品 Garmin $199/Fitbit $149，建议定价 $129，英文本地化需强调健康追踪"
			}
			return "建议参考当地主流竞品定价，做本地语言+文化适配"
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
	fmt.Println("\n=== Agent 注册上线 ===")

	type agentInfo struct {
		id *savedIdentity
	}
	agents := make([]agentInfo, len(experts))

	for i, exp := range experts {
		expCopy := exp
		shortTopic := exp.topic
		idPath := fmt.Sprintf("identity-worker-%d-%s.json", i+1, apiPort)

		fmt.Printf("\n[%d/%d] %s\n", i+1, len(experts), exp.name)

		fmt.Print("  生成身份...")
		id, err := loadOrCreateIdentity(idPath, c)
		if err != nil {
			fatal("身份初始化 [%s]: %v", exp.name, err)
		}
		fmt.Printf(" AID: %s\n", shortAID(id.AID))

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatal("启动 HTTP 服务 [%s]: %v", exp.name, err)
		}
		svcAddr := fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)

		fmt.Print("  注册 agent...")
		if err := setupAgent(c, id, svcAddr); err != nil {
			fatal("注册 [%s]: %v", exp.name, err)
		}
		fmt.Println(" OK")

		fmt.Printf("  注册服务 %s...", shortTopic)
		topicReq := map[string]any{
			"services":  []string{exp.topic},
			"name":      exp.name,
			"protocols": []string{"http"},
			"tags":      exp.tags,
			"brief":     exp.brief,
			"ttl":       3600,
		}
		if err := c.do("POST", "/agents/"+id.AID+"/services", topicReq, nil); err != nil {
			fatal("注册服务 [%s]: %v", exp.name, err)
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
			fmt.Printf("\n  [%s] 收到来自 %s 的咨询\n  → %s\n",
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
				fmt.Fprintf(os.Stderr, "[%s] HTTP 错误: %v\n", expCopy.name, err)
			}
		}()

		fmt.Printf("  ✓ 已上线\n")
		agents[i] = agentInfo{id: id}
	}

	fmt.Printf(`
Agent 已上线，等待调用（Ctrl-C 退出）
可在 Web UI 的 Discover 标签页搜索以下服务名查看各 Agent:
  reason.evaluate  /  data.search  /  reason.analyze  /  reason.recommend

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
	fmt.Println("\n=== 出海决策 — Planner ===")
	fmt.Println()

	idPath := fmt.Sprintf("identity-planner-%s.json", apiPort)
	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fatal("身份初始化: %v", err)
	}
	fmt.Printf("  Planner AID: %s\n\n", shortAID(id.AID))

	regReq := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
	}
	if err := c.do("POST", "/agents", regReq, nil); err != nil {
		if !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "conflict") {
			fatal("注册 planner: %v", err)
		}
	}

	product := "智能手表"
	market := "欧盟"
	fmt.Printf("  任务: %s → %s 市场\n\n", product, market)

	// Discover agents in parallel; print each as it's found.
	fmt.Println("  搜索 Tangled 网络...")
	type discovery struct {
		topic string
		aid   string
		name  string
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
					discoveryCh <- discovery{exp.topic, resp.Entries[0].AID, resp.Entries[0].Name}
					return
				}
			}
			discoveryCh <- discovery{exp.topic, "", ""}
		}()
	}

	discovered := make([]discovery, 0, len(experts))
	for range experts {
		d := <-discoveryCh
		if d.aid != "" {
			fmt.Printf("  发现: %-28s  %s  (%s)\n", d.name, shortAID(d.aid), d.topic)
			discovered = append(discovered, d)
		} else {
			fmt.Printf("  未找到: %-26s  跳过\n", d.topic)
		}
	}

	if len(discovered) == 0 {
		fatal("未在网络中找到任何可用 Agent。\n请先启动 Worker 并等待其打印「已上线」后再运行 Planner。")
	}

	fmt.Printf("\n  建立 Agent Swarm（%d 个 Agent）\n", len(discovered))
	fmt.Println("  开始并行处理...\n")

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
			if err := c.do("POST", "/connect/"+d.aid,
				map[string]any{"local_aid": id.AID}, &connResp); err != nil {
				results <- expertResult{topic: d.topic, name: d.name, aid: d.aid,
					err: fmt.Errorf("建立隧道失败: %w", err)}
				return
			}

			hc := &http.Client{Timeout: 15 * time.Second}
			body, _ := json.Marshal(map[string]string{
				"product": product,
				"market":  market,
			})
			resp, err := hc.Post("http://"+connResp.Tunnel+"/consult",
				"application/json", bytes.NewReader(body))
			if err != nil {
				results <- expertResult{topic: d.topic, name: d.name, aid: d.aid,
					err: fmt.Errorf("HTTP 调用失败: %w", err)}
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
  出海方案汇总  %s → %s
  ══════════════════════════════════
`, product, market)

	labels := []struct{ topic, label string }{
		{"reason.evaluate", "合规"},
		{"data.search", "物流"},
		{"reason.analyze", "关税"},
		{"reason.recommend", "本地化"},
	}
	for _, l := range labels {
		if r, ok := collected[l.topic]; ok && r.err == nil {
			fmt.Printf("  %-6s: %s\n", l.label, r.result)
		} else {
			fmt.Printf("  %-6s: （专家离线，信息缺失）\n", l.label)
		}
	}

	fmt.Printf(`  ══════════════════════════════════

✓ Demo6 验证完成
  验证链路:
    1. 多 Agent 身份生成与注册（Worker 内 4 个独立 AID）
    2. 多 topic 服务发布到 DHT（domain.*）
    3. Planner 并行 Discover 发现专家
    4. 并行建立 %d 条 QUIC 隧道（携带 Planner 身份）
    5. HTTP-over-QUIC 并发调用 + gateway AID 头验证
    6. 结果聚合为出海方案

`, len(discovered))
}

// ─── Main ────────────────────────────────────────────────────────────────────

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\n错误: "+format+"\n", args...)
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
		default:
			fmt.Fprintf(os.Stderr, "未知参数: %s\n", arg)
			os.Exit(1)
		}
	}

	if role == "" {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  go run . --role worker   [--api 127.0.0.1:2121] [--token TOKEN]")
		fmt.Fprintln(os.Stderr, "  go run . --role planner  [--api 127.0.0.1:2122] [--token TOKEN]")
		os.Exit(1)
	}

	apiPort := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
	c := newClient(apiAddr, token)
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法连接到 a2ald (%s): %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "请先启动 a2ald，例如: a2ald --data-dir ./tmp/worker --fallback-host 127.0.0.1")
		os.Exit(1)
	}

	switch role {
	case "worker":
		runWorker(c, apiPort)
	case "planner":
		runPlanner(c, apiPort)
	default:
		fmt.Fprintf(os.Stderr, "未知角色 %q，请使用 worker 或 planner\n", role)
		os.Exit(1)
	}
}
