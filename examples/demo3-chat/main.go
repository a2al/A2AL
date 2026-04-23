// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// demo3-chat: chat via the a2ald REST API (stdlib only).
//
// Unlike demo2-chat, this program does not import the a2al Go library (stdlib only).
// Transport, DHT, QUIC, and NAT traversal are handled by a2ald; this demo controls a2ald via
// its REST API and exchanges messages over TCP.
//
// Prerequisite: start a2ald in another terminal. Bob enters Alice's printed AID to chat.
// Without Go, use the pre-built demo3-chat binary from the demos-latest release (see doc/examples.md).
//
// Recommended -- two machines, two terminals each:
//
//	Machine A: a2ald  +  demo3-chat
//	Machine B: a2ald  +  demo3-chat
//
// Single machine -- four terminals (two daemons as each other's bootstrap; needs --fallback-host):
//
//	Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
//	Alice chat:   demo3-chat
//	Bob a2ald:    a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
//	              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
//	Bob chat:     demo3-chat --api 127.0.0.1:2122
//
// Build from source (Go 1.22+): replace "demo3-chat" with "go run ." inside examples/demo3-chat/.
//
// LAN testing: set --fallback-host to this host's LAN IP; set --bootstrap to the peer's ip:4121.
//
// If a2ald enables api_token, add --token TOKEN to this demo.
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
//   --api HOST:PORT   REST address of the a2ald this demo talks to (default 127.0.0.1:2121)
//   --token TOKEN     a2ald api_token (required if the daemon enables authentication)
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// --- REST client ---------------------------------------------------------------

type client struct {
	base   string
	token  string
	http   *http.Client
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

// --- API types -----------------------------------------------------------------

type identityGenResp struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
}

type registerReq struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

type patchAgentReq struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

type connectResp struct {
	Tunnel string `json:"tunnel"`
}

// --- Chat service (TCP server) -------------------------------------------------

// chatServer listens on a random local TCP port. a2ald gateway forwards inbound
// QUIC streams here. Each accepted connection begins with a 21-byte remote AID
// header (spec ?gateway), followed by UTF-8 chat messages (newline-delimited).
type chatServer struct {
	ln      net.Listener
	myAID   string
	inbound chan *chatConn
}

type chatConn struct {
	remoteAID string
	conn      net.Conn
	rd        *bufio.Reader
}

func newChatServer(myAID string) (*chatServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &chatServer{ln: ln, myAID: myAID, inbound: make(chan *chatConn, 4)}
	go s.accept()
	return s, nil
}

// serviceTCP returns host:port for a2ald to dial. Always use 127.0.0.1 + port so
// Windows / dual-stack listeners do not report an address a2ald cannot probe.
func (s *chatServer) serviceTCP() string {
	ta, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		return s.ln.Addr().String()
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(ta.Port))
}

func (s *chatServer) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *chatServer) handle(conn net.Conn) {
	// Read 21-byte remote AID header written by a2ald gateway.
	var hdr [21]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		conn.Close()
		return
	}
	remoteAID := aidBytesToString(hdr[:])
	s.inbound <- &chatConn{
		remoteAID: remoteAID,
		conn:      conn,
		rd:        bufio.NewReader(conn),
	}
}

func (s *chatServer) close() { s.ln.Close() }

// aidBytesToString encodes the 21-byte AID as a 42-char lowercase hex string.
// This matches what ParseAddress accepts and is consistent enough for display
// (Address.String() uses checksummed mixed case, but lowercase is also valid).
func aidBytesToString(b []byte) string {
	if len(b) < 21 {
		return "unknown"
	}
	const hex = "0123456789abcdef"
	buf := make([]byte, 42)
	for i, c := range b[:21] {
		buf[i*2] = hex[c>>4]
		buf[i*2+1] = hex[c&0xf]
	}
	return string(buf)
}

// --- Identity persistence ------------------------------------------------------

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
	var resp identityGenResp
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

// --- Main ----------------------------------------------------------------------

func main() {
	apiAddr := "127.0.0.1:2121"
	token := ""
	idPath := ""
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--api" && i+1 < len(os.Args):
			i++; apiAddr = os.Args[i]
		case arg == "--token" && i+1 < len(os.Args):
			i++; token = os.Args[i]
		case arg == "--id" && i+1 < len(os.Args):
			i++; idPath = os.Args[i]
		case strings.HasPrefix(arg, "--api="):
			apiAddr = strings.TrimPrefix(arg, "--api=")
		case strings.HasPrefix(arg, "--token="):
			token = strings.TrimPrefix(arg, "--token=")
		case strings.HasPrefix(arg, "--id="):
			idPath = strings.TrimPrefix(arg, "--id=")
		}
	}
	if idPath == "" {
		// Default: identity file alongside the API address (port-specific).
		port := apiAddr[strings.LastIndex(apiAddr, ":")+1:]
		idPath = "identity-" + port + ".json"
	}

	c := newClient(apiAddr, token)

	// Check a2ald is alive.
	if err := c.do("GET", "/health", nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach a2ald at %s: %v\n", apiAddr, err)
		fmt.Fprintln(os.Stderr, "Make sure a2ald is running. Download: https://github.com/a2al/a2al/releases")
		fmt.Fprintln(os.Stderr, "See doc/examples.md or https://github.com/a2al/a2al for setup instructions.")
		os.Exit(1)
	}

	// Load or generate identity.
	id, err := loadOrCreateIdentity(idPath, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// Start local TCP chat server.
	srv, err := newChatServer(id.AID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: tcp listen:", err)
		os.Exit(1)
	}
	defer srv.close()

	// Register with a2ald.
	var regResp map[string]string
	if err := c.do("POST", "/agents", registerReq{
		OperationalPrivateKeyHex: id.OperationalPrivateKeyHex,
		DelegationProofHex:       id.DelegationProofHex,
		ServiceTCP:               srv.serviceTCP(),
	}, &regResp); err != nil {
		// 409 = already registered: refresh service_tcp (new random port each run).
		if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "conflict") {
			if err := c.do("PATCH", "/agents/"+id.AID, patchAgentReq{
				OperationalPrivateKeyHex: id.OperationalPrivateKeyHex,
				ServiceTCP:               srv.serviceTCP(),
			}, nil); err != nil {
				fmt.Fprintln(os.Stderr, "update service_tcp:", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "register:", err)
			os.Exit(1)
		}
	}

	// Publish endpoint.
	if err := c.do("POST", "/agents/"+id.AID+"/publish", struct{}{}, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: publish endpoint failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "")
		if strings.Contains(err.Error(), "service_tcp unreachable") {
			fmt.Fprintf(os.Stderr, "a2ald could not TCP-dial service_tcp (%s) from the daemon process.\n", srv.serviceTCP())
			fmt.Fprintln(os.Stderr, "Require: demo3-chat and a2ald on the same machine (not API-only SSH tunnel); chat must listen on 127.0.0.1.")
			fmt.Fprintln(os.Stderr, "If you changed code, rebuild a2ald.exe; stale agents.json with wrong port: delete that agent or data-dir agents.json.")
		} else {
			fmt.Fprintln(os.Stderr, "If the error is not about service_tcp, a2ald may be unable to build a public endpoint.")
			fmt.Fprintln(os.Stderr, "For local tests add:  --fallback-host 127.0.0.1")
		}
		os.Exit(1)
	}

	printBanner(id.AID)

	// Main REPL.
	stdinCh := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			stdinCh <- sc.Text()
		}
		close(stdinCh)
	}()

	var active *chatConn // non-nil while in chat mode

	prompt := func() {
		if active != nil {
			short := active.remoteAID
			if len(short) > 16 {
				short = short[:16] + "..."
			}
			fmt.Printf("[chat -> %s] ", short)
		} else {
			fmt.Print("> ")
		}
	}
	prompt()

	for {
		select {

		case cc := <-srv.inbound:
			fmt.Printf("\n[inbound] %s wants to chat\n", cc.remoteAID)
			active = cc
			go readLoop(cc, func(msg string) {
				fmt.Printf("\n[%s...] %s\n", cc.remoteAID[:min(16, len(cc.remoteAID))], msg)
				prompt()
			}, func() {
				fmt.Println("\n[peer disconnected]")
				if active == cc {
					active = nil
				}
				prompt()
			})
			fmt.Println("[chat mode -- empty line to exit]")
			prompt()

		case line, ok := <-stdinCh:
			if !ok {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if active != nil {
				if strings.TrimSpace(line) == "" {
					fmt.Println("(chat ended)")
					_ = active.conn.Close()
					active = nil
					prompt()
					continue
				}
				_, err := fmt.Fprintf(active.conn, "%s\n", line)
				if err != nil {
					fmt.Println("(send error -- chat ended)")
					active = nil
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
			if line == "aid" || line == "me" {
				fmt.Println("My AID:", id.AID)
				prompt()
				continue
			}
			// Treat input as peer AID.
			if err := connectToPeer(c, id.AID, line, func(cc *chatConn) {
				active = cc
				go readLoop(cc, func(msg string) {
					fmt.Printf("\n[%s...] %s\n", cc.remoteAID[:min(16, len(cc.remoteAID))], msg)
					prompt()
				}, func() {
					fmt.Println("\n[peer disconnected]")
					if active == cc {
						active = nil
					}
					prompt()
				})
				fmt.Println("Connected! [chat mode -- empty line to exit]")
				prompt()
			}); err != nil {
				fmt.Println("connect failed:", err)
				prompt()
			}
		}
	}
}

// connectToPeer calls POST /connect/{aid}, connects the tunnel TCP, and calls
// onConnected once the outbound chatConn is ready.
func connectToPeer(c *client, localAID, peerAID string, onConnected func(*chatConn)) error {
	fmt.Printf("Connecting to %s...\n", peerAID)
	var resp connectResp
	type connectBody struct {
		LocalAID string `json:"local_aid,omitempty"`
	}
	if err := c.do("POST", "/connect/"+peerAID, connectBody{LocalAID: localAID}, &resp); err != nil {
		return err
	}
	if resp.Tunnel == "" {
		return errors.New("no tunnel address in response")
	}
	conn, err := net.DialTimeout("tcp", resp.Tunnel, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial tunnel %s: %w", resp.Tunnel, err)
	}
	cc := &chatConn{
		remoteAID: peerAID,
		conn:      conn,
		rd:        bufio.NewReader(conn),
	}
	onConnected(cc)
	return nil
}

// readLoop reads newline-delimited messages from cc until EOF.
func readLoop(cc *chatConn, onMsg func(string), onClose func()) {
	defer onClose()
	for {
		line, err := cc.rd.ReadString('\n')
		if len(line) > 0 {
			onMsg(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			return
		}
	}
}

func printBanner(aid string) {
	fmt.Println()
	fmt.Println("======================================================")
	fmt.Println("  demo3-chat  (powered by a2ald)")
	fmt.Println("  My AID:", aid)
	fmt.Println("======================================================")
	fmt.Println()
	fmt.Println("Waiting for inbound connections...")
	fmt.Println("Commands:")
	fmt.Println("  <peer AID>   -> connect to peer and start chatting")
	fmt.Println("  aid          -- print my AID again")
	fmt.Println("  quit         -- exit")
	fmt.Println()
}


