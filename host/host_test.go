// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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

func TestHost_quicTLSAndStream(t *testing.T) {
	ksA, ksB := newMemKS(t), newMemKS(t)
	ha, err := New(Config{
		KeyStore: ksA, ListenAddr: "127.0.0.1:0", QUICListenAddr: "127.0.0.1:0",
		PrivateKey: ksA.priv, MinObservedPeers: 1, FallbackHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ha.Close()
	hb, err := New(Config{
		KeyStore: ksB, ListenAddr: "127.0.0.1:0", QUICListenAddr: "127.0.0.1:0",
		PrivateKey: ksB.priv, MinObservedPeers: 1, FallbackHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		c, err := ha.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		str, err := c.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := str.Read(buf); err != nil {
			errCh <- err
			return
		}
		if _, err := str.Write(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	conn, err := hb.Connect(ctx, ha.Address(), ha.QUICLocalAddr())
	if err != nil {
		t.Fatal("Connect:", err)
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal("OpenStreamSync:", err)
	}
	if _, err := str.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := str.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo want ping got %q", buf)
	}
	if err := <-errCh; err != nil {
		t.Fatal("server:", err)
	}
}
