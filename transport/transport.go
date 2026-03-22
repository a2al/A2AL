// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"net"
)

// MaxPacketSize is the UDP payload cap (spec §3.7, IPv6-safe 1200).
const MaxPacketSize = 1200

var (
	// ErrPacketTooLarge is returned when Send payload exceeds MaxPacketSize.
	ErrPacketTooLarge = errors.New("a2al/transport: packet exceeds MaxPacketSize")
	// ErrClosed is returned after the transport is closed.
	ErrClosed = errors.New("a2al/transport: closed")
	// ErrUnknownPeer is returned by MemTransport when the destination is not registered.
	ErrUnknownPeer = errors.New("a2al/transport: unknown mem peer")
	// ErrDuplicatePeer is returned when a MemTransport name is already bound.
	ErrDuplicatePeer = errors.New("a2al/transport: duplicate mem peer name")
	// ErrMemBufferFull is returned when the peer inbox is full (backpressure).
	ErrMemBufferFull = errors.New("a2al/transport: mem peer inbox full")
)

// Transport is the DHT packet plane (spec §3.3).
type Transport interface {
	Send(addr net.Addr, data []byte) error
	Receive() ([]byte, net.Addr, error)
	LocalAddr() net.Addr
	Close() error
}
