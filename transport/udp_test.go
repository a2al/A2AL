package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestUDPTransport_localhost(t *testing.T) {
	t1, err := ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	defer t2.Close()

	a2 := t2.LocalAddr().(*net.UDPAddr)
	msg := []byte("hello-udp-a2al")
	if err := t1.Send(a2, msg); err != nil {
		t.Fatal(err)
	}
	got, from, err := t2.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal(string(got))
	}
	if from.String() != t1.LocalAddr().String() {
		t.Fatalf("from %s want %s", from, t1.LocalAddr())
	}
}

func TestUDPTransport_packetTooLarge(t *testing.T) {
	t1, err := ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	err = t1.Send(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, make([]byte, MaxPacketSize+1))
	if err != ErrPacketTooLarge {
		t.Fatalf("got %v", err)
	}
}
