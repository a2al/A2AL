// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"net"
	"sync"
)

// Addr is a logical in-memory address (net.Addr, Network "mem").
type Addr struct {
	Name string
}

// Network implements net.Addr.
func (a Addr) Network() string { return "mem" }

// String implements net.Addr.
func (a Addr) String() string { return a.Name }

type memPacket struct {
	payload []byte
	from    net.Addr
}

// MemNetwork links MemTransport instances for process-local testing (spec §3.4).
type MemNetwork struct {
	mu   sync.Mutex
	peer map[string]chan memPacket
}

// NewMemNetwork creates an empty network.
func NewMemNetwork() *MemNetwork {
	return &MemNetwork{peer: make(map[string]chan memPacket)}
}

// NewTransport registers a peer name and returns a transport bound to it.
func (n *MemNetwork) NewTransport(name string) (*MemTransport, error) {
	ch := make(chan memPacket, 256)
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, dup := n.peer[name]; dup {
		return nil, ErrDuplicatePeer
	}
	n.peer[name] = ch
	return &MemTransport{net: n, local: Addr{Name: name}, inbox: ch}, nil
}

// MemTransport delivers packets via MemNetwork.
type MemTransport struct {
	net   *MemNetwork
	local Addr
	inbox chan memPacket
	once  sync.Once
}

func (t *MemTransport) LocalAddr() net.Addr { return t.local }

func (t *MemTransport) Send(addr net.Addr, data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	key := addr.String()
	t.net.mu.Lock()
	ch, ok := t.net.peer[key]
	t.net.mu.Unlock()
	if !ok {
		return ErrUnknownPeer
	}
	p := memPacket{
		payload: append([]byte(nil), data...),
		from:    t.local,
	}
	select {
	case ch <- p:
		return nil
	default:
		return ErrMemBufferFull
	}
}

func (t *MemTransport) Receive() ([]byte, net.Addr, error) {
	p, ok := <-t.inbox
	if !ok {
		return nil, nil, ErrClosed
	}
	return p.payload, p.from, nil
}

func (t *MemTransport) Close() error {
	t.once.Do(func() {
		t.net.mu.Lock()
		delete(t.net.peer, t.local.String())
		t.net.mu.Unlock()
		close(t.inbox)
	})
	return nil
}
