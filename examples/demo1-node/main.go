// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo1-node: 单一 A2AL DHT 节点。
//
// 启动后自动生成身份、监听 UDP、bootstrap（若提供种子）、发布自己的端点记录。
// 然后等待用户在 stdin 输入 Address 进行解析查询。
//
// 用法:
//   go run . -listen :4121 -ip 1.2.3.4 -debug :2634
//   go run . -listen :4122 -ip 1.2.3.5 -bootstrap 1.2.3.4:4121 -debug :2635
//
// 浏览器查看节点状态:
//   http://127.0.0.1:2634/debug/identity
//   http://127.0.0.1:2634/debug/routing
//   http://127.0.0.1:2634/debug/store
//   http://127.0.0.1:2634/debug/stats
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func main() {
	listen := flag.String("listen", ":4121", "UDP listen address")
	bootstrapAddr := flag.String("bootstrap", "", "seed node UDP address (e.g. 127.0.0.1:4121)")
	debugAddr := flag.String("debug", "", "debug HTTP address (e.g. 127.0.0.1:2634)")
	extIP := flag.String("ip", "", "external IP for endpoint record (e.g. 1.2.3.4)")
	flag.Parse()

	ks, err := newSimpleKS()
	if err != nil {
		log.Fatal(err)
	}

	tr, err := transport.ListenUDP("udp4", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer tr.Close()

	node, err := dht.NewNode(dht.Config{Transport: tr, Keystore: ks})
	if err != nil {
		log.Fatal(err)
	}
	defer node.Close()

	node.Start()

	if *debugAddr != "" {
		stop, err := node.StartDebugHTTP(*debugAddr)
		if err != nil {
			log.Fatal("debug http:", err)
		}
		defer stop()
		fmt.Printf("Debug HTTP: http://%s/debug/identity\n", *debugAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *bootstrapAddr != "" {
		seedUDP, err := net.ResolveUDPAddr("udp4", *bootstrapAddr)
		if err != nil {
			log.Fatal("resolve bootstrap addr:", err)
		}
		bctx, bcancel := context.WithTimeout(ctx, 15*time.Second)
		defer bcancel()
		if err := node.BootstrapAddrs(bctx, []net.Addr{seedUDP}); err != nil {
			log.Println("bootstrap warning:", err)
		} else {
			fmt.Println("Bootstrap OK")
		}
	}

	localUDP := tr.LocalAddr().(*net.UDPAddr)
	host := *extIP
	if host == "" {
		if localUDP.IP.IsUnspecified() {
			host = "127.0.0.1"
		} else {
			host = localUDP.IP.String()
		}
	}
	endpoint := fmt.Sprintf("udp://%s:%d", host, localUDP.Port)
	payload := protocol.EndpointPayload{Endpoints: []string{endpoint}, NatType: protocol.NATUnknown}

	publish := func() {
		now := time.Now().Truncate(time.Second)
		rec, err := protocol.SignEndpointRecord(ks.priv, ks.addr, payload, 1, uint64(now.Unix()), 3600)
		if err != nil {
			log.Println("sign record:", err)
			return
		}
		pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
		defer pcancel()
		if err := node.PublishEndpointRecord(pctx, rec); err != nil {
			log.Println("publish warning:", err)
		} else {
			fmt.Println("Published endpoint record")
		}
	}

	publish()

	// Re-publish every 30 min so the record stays fresh within the 1 h TTL.
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				publish()
			case <-ctx.Done():
				return
			}
		}
	}()

	fmt.Println()
	fmt.Println("My address:", ks.addr.String())
	fmt.Println("Listening:", tr.LocalAddr())
	fmt.Println()
	fmt.Println("Enter an Address to resolve (or 'quit'):")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "quit" || line == "exit" {
			break
		}

		addr, err := a2al.ParseAddress(line)
		if err != nil {
			fmt.Println("invalid address:", err)
			continue
		}
		key := a2al.NodeIDFromAddress(addr)
		rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
		q := dht.NewQuery(node)
		er, err := q.Resolve(rctx, key)
		rcancel()
		if err != nil {
			fmt.Println("resolve failed:", err)
			continue
		}
		fmt.Printf("resolved %s → endpoints: %v\n", line, er.Endpoints)
	}
}
