package transport

import (
	"bytes"
	"testing"
)

func TestMemTransport_roundTrip(t *testing.T) {
	netw := NewMemNetwork()
	a, err := netw.NewTransport("a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := netw.NewTransport("b")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	payload := []byte{1, 2, 3, 0xfe}
	if err := a.Send(b.LocalAddr(), payload); err != nil {
		t.Fatal(err)
	}
	got, from, err := b.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload %v", got)
	}
	if from.String() != "a" {
		t.Fatal(from.String())
	}
}

func TestMemTransport_unknownPeer(t *testing.T) {
	netw := NewMemNetwork()
	a, _ := netw.NewTransport("a")
	defer a.Close()
	err := a.Send(Addr{Name: "ghost"}, []byte{1})
	if err != ErrUnknownPeer {
		t.Fatalf("got %v", err)
	}
}

func TestMemTransport_duplicateName(t *testing.T) {
	netw := NewMemNetwork()
	_, err := netw.NewTransport("x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = netw.NewTransport("x")
	if err != ErrDuplicatePeer {
		t.Fatalf("got %v", err)
	}
}

func TestSend_packetTooLarge(t *testing.T) {
	netw := NewMemNetwork()
	a, _ := netw.NewTransport("a")
	b, _ := netw.NewTransport("b")
	defer a.Close()
	defer b.Close()
	err := a.Send(b.LocalAddr(), make([]byte, MaxPacketSize+1))
	if err != ErrPacketTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestMemTransport_closeReceive(t *testing.T) {
	netw := NewMemNetwork()
	a, _ := netw.NewTransport("a")
	a.Close()
	if _, _, err := a.Receive(); err != ErrClosed {
		t.Fatalf("got %v", err)
	}
}
