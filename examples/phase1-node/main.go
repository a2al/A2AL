// Phase1-node: 单一 A2AL DHT 节点。
//
// 启动后自动生成身份、监听 UDP、bootstrap（若提供种子）、发布自己的端点记录。
// 然后等待用户在 stdin 输入 Address 进行解析查询。
//
// 用法:
//   go run . -listen :5001 -debug :2634
//   go run . -listen :5002 -bootstrap 127.0.0.1:5001 -debug :2635
//   go run . -listen :5003 -bootstrap 127.0.0.1:5001 -debug :2636
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
	listen := flag.String("listen", ":5001", "UDP listen address")
	bootstrapAddr := flag.String("bootstrap", "", "seed node UDP address (e.g. 127.0.0.1:5001)")
	debugAddr := flag.String("debug", "", "debug HTTP address (e.g. 127.0.0.1:2634)")
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
	endpoint := fmt.Sprintf("udp://%s:%d", localUDP.IP, localUDP.Port)
	if localUDP.IP.IsUnspecified() {
		endpoint = fmt.Sprintf("udp://127.0.0.1:%d", localUDP.Port)
	}
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
