// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo2-chat: Encrypted two-party chat over the Tangled network (multi-candidate QUIC endpoints; try multiple paths).
//
// Covers:
//   Publish / Resolve / ConnectFromRecord / Accept / mutual TLS / agent-route / nat-sense / UPnP (optional)
//
// Without Go, use the pre-built demo2-chat binary from the demos-latest release (replace go run . with demo2-chat; same flags).
//
// Steps:
//
// Recommended — two machines (one terminal each):
//
//   Alice:  go run .
//   Bob:    go run . -bootstrap <Alice-IP>:4121
//
// Single machine — two terminals (different listen ports):
//
//   Terminal 1 (Alice):  go run . -listen :4121
//   Terminal 2 (Bob):    go run . -listen :4123 -bootstrap 127.0.0.1:4121
//
// On Bob, enter Alice’s AID → resolve + QUIC connect → chat. Default QUIC shares the DHT UDP port;
// use -quic if you need a separate QUIC listener.
//
// Optional flags:
//   -debug :2634  start debug HTTP; open http://127.0.0.1:2634/debug/host for host state
//   -ip            advertise this host when you must pin a specific egress IP / interface
//
// Debug HTTP (browser):
//   http://127.0.0.1:2634/debug/host     — host state
//   http://127.0.0.1:2634/debug/identity — DHT identity
//   http://127.0.0.1:2634/debug/routing  — routing table
//   http://127.0.0.1:2634/debug/store    — endpoint record store
//   http://127.0.0.1:2634/debug/stats    — traffic stats
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

func main() {
	listen := flag.String("listen", ":4121", "Tangled Network UDP listen address")
	quicListen := flag.String("quic", "", "QUIC UDP listen (empty = share Tangled port)")
	bootstrapAddr := flag.String("bootstrap", "", "seed Tangled Network UDP address")
	debugAddr := flag.String("debug", "", "debug HTTP address")
	extIP := flag.String("ip", "", "advertise host (fallback)")
	minObs := flag.Int("min-observed", 1, "nat-sense threshold")
	noUPnP := flag.Bool("no-upnp", false, "disable UPnP port mapping")
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
		DisableUPnP:      *noUPnP,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	if *debugAddr != "" {
		stop, err := h.StartDebugHTTP(*debugAddr)
		if err != nil {
			log.Fatal("debug http:", err)
		}
		defer stop()
		fmt.Printf("Debug HTTP: http://%s/debug/host\n", *debugAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *bootstrapAddr != "" {
		seedUDP, err := net.ResolveUDPAddr("udp4", *bootstrapAddr)
		if err != nil {
			log.Fatal(err)
		}
		bctx, bcancel := context.WithTimeout(ctx, 15*time.Second)
		if err := h.Node().BootstrapAddrs(bctx, []net.Addr{seedUDP}); err != nil {
			log.Println("bootstrap warning:", err)
		} else {
			fmt.Println("Bootstrap OK")
		}
		bcancel()
		obctx, obcancel := context.WithTimeout(ctx, 10*time.Second)
		h.ObserveFromPeers(obctx, []net.Addr{seedUDP})
		obcancel()
	}

	pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
	if err := h.PublishEndpoint(pctx, 1, 3600); err != nil {
		log.Println("publish:", err)
	} else {
		fmt.Println("Published endpoint record")
	}
	pcancel()

	natLabels := []string{"unknown", "full_cone", "restricted", "port_restricted", "symmetric"}
	natStr := natLabels[0]
	if t := h.Sense().InferNATType(); int(t) < len(natLabels) {
		natStr = natLabels[t]
	}
	if hint := h.SymmetricNATReachabilityHint(); hint != "" {
		fmt.Println("Note:", hint)
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  My AID:    ", ks.addr.String())
	fmt.Println("  Tangled UDP:", h.DHTLocalAddr())
	fmt.Println("  QUIC UDP:  ", h.QUICLocalAddr())
	fmt.Printf("  NAT type:   %s\n", natStr)
	if oh, op, ok := h.Sense().TrustedUDP(); ok {
		fmt.Printf("  Observed:   %s:%d\n", oh, op)
	}
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()
	fmt.Println("Waiting for inbound connections...")
	fmt.Println("Enter a peer AID to connect and chat, or 'quit' to exit.")

	// Single stdin reader → all input flows through one channel.
	stdinCh := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			stdinCh <- sc.Text()
		}
		close(stdinCh)
	}()

	// Inbound connections → channel, consumed by main loop.
	inboundCh := make(chan *host.AgentConn, 4)
	go func() {
		for {
			ac, err := h.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Println("accept error:", err)
				continue
			}
			inboundCh <- ac
		}
	}()

	// activeStream is set while in chat mode; nil = REPL mode.
	var activeStream quic.Stream
	var activePeer a2al.Address

	prompt := func() {
		if activeStream != nil {
			fmt.Printf("[chat → %s] ", activePeer.String()[:12]+"…")
		} else {
			fmt.Print("> ")
		}
	}
	prompt()

	for {
		select {
		case ac, ok := <-inboundCh:
			if !ok {
				return
			}
			fmt.Printf("\n[inbound] peer %s\n", ac.Remote)
			str, err := ac.Connection.AcceptStream(ctx)
			if err != nil {
				log.Println("accept stream:", err)
				prompt()
				continue
			}
			activeStream = str
			activePeer = ac.Remote
			go printIncoming(str, ac.Remote)
			fmt.Printf("[chat mode — empty line to exit]\n")
			prompt()

		case line, ok := <-stdinCh:
			if !ok {
				return
			}
			if activeStream != nil {
				if strings.TrimSpace(line) == "" {
					fmt.Println("(chat ended)")
					activeStream = nil
					activePeer = a2al.Address{}
					prompt()
					continue
				}
				if _, err := fmt.Fprintf(activeStream, "%s\n", line); err != nil {
					fmt.Println("send error:", err)
					activeStream = nil
				}
				prompt()
				continue
			}
			// REPL mode.
			line = strings.TrimSpace(line)
			if line == "" {
				prompt()
				continue
			}
			if line == "quit" || line == "exit" {
				return
			}
			addr, err := a2al.ParseAddress(line)
			if err != nil {
				fmt.Println("invalid AID:", err)
				prompt()
				continue
			}
			fmt.Printf("Resolving %s ...\n", addr)
			rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
			er, err := h.Resolve(rctx, addr)
			rcancel()
			if err != nil {
				fmt.Println("resolve failed:", err)
				prompt()
				continue
			}
			if len(er.Endpoints) > 0 {
				fmt.Printf("Resolved → %d QUIC candidate(s), connecting...\n", len(er.Endpoints))
			}
			cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
			conn, err := h.ConnectFromRecord(cctx, addr, er)
			ccancel()
			if err != nil {
				fmt.Println("connect failed:", err)
				prompt()
				continue
			}
			str, err := conn.OpenStreamSync(ctx)
			if err != nil {
				fmt.Println("open stream:", err)
				prompt()
				continue
			}
			activeStream = str
			activePeer = addr
			go printIncoming(str, addr)
			fmt.Println("Connected! [chat mode — empty line to exit]")
			prompt()
		}
	}
}

func printIncoming(str quic.Stream, peer a2al.Address) {
	br := bufio.NewReader(str)
	prefix := peer.String()[:12] + "…"
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			fmt.Printf("\n[%s] %s\n> ", prefix, strings.TrimRight(line, "\n"))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read error from %s: %v", prefix, err)
			}
			return
		}
	}
}
