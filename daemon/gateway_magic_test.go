// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/a2al/a2al/protocol"
)

func coalescedGroupStream(t *testing.T) (payload []byte, gid [32]byte) {
	t.Helper()
	for i := range gid {
		gid[i] = byte(i + 1)
	}
	payload = append([]byte(protocol.MagicGroupSync), gid[:]...)
	payload = append(payload, []byte("HAVE")...)
	return payload, gid
}

func TestTakeStreamMagic_CoalescedGroupIDUnshifted(t *testing.T) {
	payload, gid := coalescedGroupStream(t)
	r := bytes.NewReader(payload)

	magic, n, err := takeStreamMagic(r)
	if err != nil || n != 4 || string(magic[:]) != protocol.MagicGroupSync {
		t.Fatalf("magic: n=%d err=%v got=%q", n, err, magic[:])
	}

	var got [32]byte
	if _, err := io.ReadFull(r, got[:]); err != nil {
		t.Fatal(err)
	}
	if got != gid {
		t.Fatalf("group_id shifted: got %x want %x (first4=%x)", got, gid, got[:4])
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "HAVE" {
		t.Fatalf("rest %q", rest)
	}
}

func TestTakeStreamMagic_CoalescedMailboxMsgIDUnshifted(t *testing.T) {
	var msgID [32]byte
	for i := range msgID {
		msgID[i] = byte(255 - i)
	}
	payload := append([]byte(protocol.MagicMailboxFrame), msgID[:]...)
	payload = append(payload, 0, 0, 0, 1, 0xab)
	r := bytes.NewReader(payload)

	magic, n, err := takeStreamMagic(r)
	if err != nil || n != 4 || string(magic[:]) != protocol.MagicMailboxFrame {
		t.Fatalf("magic: n=%d err=%v", n, err)
	}
	var got [32]byte
	if _, err := io.ReadFull(r, got[:]); err != nil {
		t.Fatal(err)
	}
	if got != msgID {
		t.Fatalf("msg_id shifted: got %x want %x", got, msgID)
	}
}

func TestTakeStreamMagic_CoalescedServiceAdmissionUnshifted(t *testing.T) {
	payload := append([]byte(protocol.MagicServiceStream), 0x02, 0x00, 0x00, 0x00, 0x00)
	r := bytes.NewReader(payload)
	magic, n, err := takeStreamMagic(r)
	if err != nil || n != 4 || string(magic[:]) != protocol.MagicServiceStream {
		t.Fatalf("magic: n=%d err=%v", n, err)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, []byte{0x02, 0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("admission bytes shifted: %x", rest)
	}
}

func TestTakeStreamMagic_CoalescedCASAdmissionUnshifted(t *testing.T) {
	payload := append([]byte(protocol.MagicCAS), 0x02, 0x00, 0x00, 0x00, 0x00)
	r := bytes.NewReader(payload)
	magic, n, err := takeStreamMagic(r)
	if err != nil || n != 4 || string(magic[:]) != protocol.MagicCAS {
		t.Fatalf("magic: n=%d err=%v", n, err)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, []byte{0x02, 0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("admission bytes shifted: %x", rest)
	}
}

func TestRestorePrefix_HTTPIntact(t *testing.T) {
	src := []byte("GET /health HTTP/1.1\r\n")
	r := bytes.NewReader(src)
	magic, n, err := takeStreamMagic(r)
	if n != 4 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if string(magic[:]) == protocol.MagicGroupSync || string(magic[:]) == protocol.MagicMailboxFrame {
		t.Fatal("HTTP prefix should not match a known magic")
	}
	rest := restorePrefix(magic[:n], r)
	got, err := io.ReadAll(rest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("HTTP stream mutated: got %q want %q", got, src)
	}
}

func TestRestorePrefix_ShortRead(t *testing.T) {
	src := []byte("ab")
	r := bytes.NewReader(src)
	magic, n, err := takeStreamMagic(r)
	if n != 2 || err != io.ErrUnexpectedEOF {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got, _ := io.ReadAll(restorePrefix(magic[:n], r))
	if !bytes.Equal(got, src) {
		t.Fatalf("got %q", got)
	}
}

// Documents the dispatcher footgun: bufio.Peek with NewReaderSize(r, 4) still
// fills ≥16 bytes, so reading the underlying stream after Discard(4) skips
// 12 payload bytes — the field-test shift that produced group id prefix
// cd9cc267. If this test starts failing because got == gid, Go's minimum
// bufio size changed and the comment in takeStreamMagic should be revisited.
func TestBufioPeek_OverreadsCoalescedGroupMagic(t *testing.T) {
	payload, _ := coalescedGroupStream(t)
	src := bytes.NewReader(payload)
	br := bufio.NewReaderSize(src, 4)
	magic, err := br.Peek(4)
	if err != nil || string(magic) != protocol.MagicGroupSync {
		t.Fatalf("peek: %q err=%v", magic, err)
	}
	if _, err := br.Discard(4); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(src)
	if err != nil {
		t.Fatal(err)
	}
	// Correct remaining after a 4-byte magic would be payload[4:] (gid+HAVE).
	if bytes.Equal(rest, payload[4:]) {
		t.Fatal("bufio no longer over-reads; takeStreamMagic comment is stale")
	}
	// Default bufio min buffer is 16: fill consumes magic+gid[:12], so
	// the underlying reader starts at gid[12:].
	if !bytes.Equal(rest, payload[16:]) {
		t.Fatalf("over-read remainder: got %x want payload[16:]=%x", rest, payload[16:])
	}
}
