// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

type memKS struct {
	priv ed25519.PrivateKey
	addr a2al.Address
}

func newMemKS(t *testing.T) *memKS {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &memKS{priv: priv, addr: addr}
}

func (m *memKS) Generate(crypto.KeyType) (crypto.PrivateKey, error) {
	return nil, errors.New("memKS: not supported")
}
func (m *memKS) Sign(addr a2al.Address, data []byte) ([]byte, error) {
	if addr != m.addr {
		return nil, errors.New("memKS: wrong address")
	}
	return ed25519.Sign(m.priv, data), nil
}
func (m *memKS) PublicKey(addr a2al.Address) ([]byte, error) {
	if addr != m.addr {
		return nil, errors.New("memKS: wrong address")
	}
	return m.priv.Public().(ed25519.PublicKey), nil
}
func (m *memKS) List() ([]a2al.Address, error) {
	return []a2al.Address{m.addr}, nil
}

func newHost(t *testing.T, ks *memKS) *Host {
	t.Helper()
	h, err := New(Config{
		KeyStore: ks, ListenAddr: "127.0.0.1:0", QUICListenAddr: "127.0.0.1:0",
		PrivateKey: ks.priv, MinObservedPeers: 1, FallbackHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestHost_quicMutualTLS(t *testing.T) {
	ksA, ksB := newMemKS(t), newMemKS(t)
	ha, hb := newHost(t, ksA), newHost(t, ksB)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type acceptResult struct {
		ac  *AgentConn
		err error
	}
	aCh := make(chan acceptResult, 1)
	go func() {
		ac, err := ha.Accept(ctx)
		aCh <- acceptResult{ac, err}
	}()

	conn, err := hb.Connect(ctx, ha.Address(), ha.QUICLocalAddr())
	if err != nil {
		t.Fatal("Connect:", err)
	}

	// Connect already sent agent-route on stream 0; open stream 1 for app data.
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal("OpenStreamSync:", err)
	}
	if _, err := str.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	ar := <-aCh
	if ar.err != nil {
		t.Fatal("Accept:", ar.err)
	}
	if ar.ac.Local != ha.Address() {
		t.Fatalf("Accept Local = %s, want %s", ar.ac.Local, ha.Address())
	}
	if ar.ac.Remote != hb.Address() {
		t.Fatalf("Accept Remote = %s, want %s", ar.ac.Remote, hb.Address())
	}

	// Accept consumes the agent-route stream; next AcceptStream is the app stream.
	sStr, err := ar.ac.AcceptStream(ctx)
	if err != nil {
		t.Fatal("AcceptStream:", err)
	}
	buf := make([]byte, 4)
	if _, err := sStr.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := sStr.Write(buf); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 4)
	if _, err := str.Read(resp); err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ping" {
		t.Fatalf("echo want ping got %q", resp)
	}
}

func TestHost_sniRouting(t *testing.T) {
	ksA := newMemKS(t)
	ha := newHost(t, ksA)

	// Register a second agent on the same host.
	_, agent2Priv, _ := ed25519.GenerateKey(rand.Reader)
	agent2Addr, _ := crypto.AddressFromPublicKey(agent2Priv.Public().(ed25519.PublicKey))
	if err := ha.RegisterAgent(agent2Addr, agent2Priv); err != nil {
		t.Fatal(err)
	}

	ksB := newMemKS(t)
	hb := newHost(t, ksB)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type acceptResult struct {
		ac  *AgentConn
		err error
	}
	aCh := make(chan acceptResult, 1)
	go func() {
		ac, err := ha.Accept(ctx)
		aCh <- acceptResult{ac, err}
	}()

	// Connect targeting agent2 specifically.
	conn, err := hb.Connect(ctx, agent2Addr, ha.QUICLocalAddr())
	if err != nil {
		t.Fatal("Connect to agent2:", err)
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := str.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	ar := <-aCh
	if ar.err != nil {
		t.Fatal("Accept:", ar.err)
	}
	if ar.ac.Local != agent2Addr {
		t.Fatalf("Accept Local = %s, want agent2 %s", ar.ac.Local, agent2Addr)
	}
	if ar.ac.Remote != hb.Address() {
		t.Fatalf("Accept Remote = %s, want %s", ar.ac.Remote, hb.Address())
	}
}
