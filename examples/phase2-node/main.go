// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Phase2-node: DHT + QUIC（host 包），可选 nat-sense。
//
// -bootstrap 填 DHT UDP 地址；若使用 -quic 独立端口，对端解析到的 udp:// 为 QUIC 端口，Connect 时用该端口。
// 小网络测试可将 -min-observed 设为 1（生产默认逻辑在库内为 ≥3 个不同节点反馈 observed_addr）。
//
// 单端口（与 spec 同端口目标，仍在验证）:
//   go run . -listen :5001 -ip 127.0.0.1
//
// 双端口（推荐测试/生产）:
//   go run . -listen :5001 -quic :5002 -ip 127.0.0.1
//   go run . -listen :5002 -quic :5003 -bootstrap 127.0.0.1:5001 -ip 127.0.0.1
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
	"github.com/a2al/a2al/host"
)

func main() {
	listen := flag.String("listen", ":5001", "DHT UDP listen address")
	quicListen := flag.String("quic", "", "QUIC UDP listen (empty = share DHT port via UDPMux)")
	bootstrapAddr := flag.String("bootstrap", "", "seed DHT UDP address, e.g. 127.0.0.1:5001")
	debugAddr := flag.String("debug", "", "debug HTTP, e.g. 127.0.0.1:2634")
	extIP := flag.String("ip", "", "advertise host for endpoint / fallback when nat-sense has no trust")
	minObs := flag.Int("min-observed", 1, "nat-sense: min distinct peers agreeing on observed UDP (use 1 for small tests; prod-oriented default in library is 3)")
	flag.Parse()

	ks, err := newSimpleKS()
	if err != nil {
		log.Fatal(err)
	}

	h, err := host.New(host.Config{
		KeyStore:         ks,
		ListenAddr:       *listen,
		QUICListenAddr:   *quicListen,
		PrivateKey:       ks.priv,
		MinObservedPeers: *minObs,
		FallbackHost:     *extIP,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	if *debugAddr != "" {
		stop, err := h.Node().StartDebugHTTP(*debugAddr)
		if err != nil {
			log.Fatal("debug http:", err)
		}
		defer stop()
		fmt.Printf("Debug HTTP: http://%s/debug/identity\n", *debugAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var seedUDP *net.UDPAddr
	if *bootstrapAddr != "" {
		seedUDP, err = net.ResolveUDPAddr("udp4", *bootstrapAddr)
		if err != nil {
			log.Fatal("bootstrap:", err)
		}
		bctx, bcancel := context.WithTimeout(ctx, 15*time.Second)
		err = h.Node().BootstrapAddrs(bctx, []net.Addr{seedUDP})
		bcancel()
		if err != nil {
			log.Println("bootstrap warning:", err)
		} else {
			fmt.Println("Bootstrap OK")
		}
		obctx, obcancel := context.WithTimeout(ctx, 10*time.Second)
		h.ObserveFromPeers(obctx, []net.Addr{seedUDP})
		obcancel()
	}

	publish := func() {
		pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
		defer pcancel()
		if err := h.PublishEndpoint(pctx, 1, 3600); err != nil {
			log.Println("publish:", err)
		} else {
			fmt.Println("Published endpoint record (QUIC udp:// in record)")
		}
	}
	publish()
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				publish()
			case <-ctx.Done():
				return
			}
		}
	}()

	fmt.Println()
	fmt.Println("My address:", ks.addr.String())
	fmt.Println("DHT UDP:   ", h.DHTLocalAddr())
	fmt.Println("QUIC UDP:  ", h.QUICLocalAddr())
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
		rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
		er, err := h.Resolve(rctx, addr)
		rcancel()
		if err != nil {
			fmt.Println("resolve failed:", err)
			continue
		}
		fmt.Printf("resolved %s → endpoints: %v\n", line, er.Endpoints)
	}
}
