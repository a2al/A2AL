package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
)

func TestPingPong_roundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	tx := make([]byte, txIDLen)
	if _, err := rand.Read(tx); err != nil {
		t.Fatal(err)
	}
	hdr := Header{Version: ProtocolVersion, Features: 0, MsgType: MsgPing, TxID: tx}
	body := &BodyPing{Address: addr[:]}
	raw, err := MarshalSignedMessage(hdr, body, priv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := VerifyAndDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Header.MsgType != MsgPing {
		t.Fatal(dec.Header.MsgType)
	}
	bp, ok := dec.Body.(*BodyPing)
	if !ok {
		t.Fatalf("body %T", dec.Body)
	}
	var got a2al.Address
	copy(got[:], bp.Address)
	if got != addr {
		t.Fatal("address mismatch")
	}
}

func TestVerify_tamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	raw, err := MarshalSignedMessage(
		Header{Version: ProtocolVersion, MsgType: MsgPing, TxID: tx},
		&BodyPing{Address: addr[:]},
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if _, err := VerifyAndDecode(raw); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerify_addressMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	var wrong a2al.Address
	copy(wrong[:], addr[:])
	wrong[20] ^= 0x01
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	raw, err := MarshalSignedMessage(
		Header{Version: ProtocolVersion, MsgType: MsgPing, TxID: tx},
		&BodyPing{Address: wrong[:]},
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAndDecode(raw); err == nil {
		t.Fatal("expected error for address / pubkey mismatch")
	}
}

func TestFindNodeResp_roundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	ip := net.IPv4(8, 8, 8, 8).To4()
	var nid a2al.NodeID
	rand.Read(nid[:])
	senderAddr, _ := acrypto.AddressFromPublicKey(pub)
	nodes := []NodeInfo{{
		Address: senderAddr[:],
		NodeID:  nid[:],
		IP:      ip,
		Port:    4242,
	}}
	obs := append(ip, byte(0x10), byte(0x92))
	body := &BodyFindNodeResp{Nodes: nodes, ObservedAddr: obs}
	raw, err := MarshalSignedMessage(
		Header{Version: ProtocolVersion, MsgType: MsgFindNodeResp, TxID: tx},
		body,
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := VerifyAndDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	br, ok := dec.Body.(*BodyFindNodeResp)
	if !ok {
		t.Fatal()
	}
	if len(br.Nodes) != 1 || br.Nodes[0].Port != 4242 {
		t.Fatal()
	}
}

func TestUnknownMsgType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	_, err := MarshalSignedMessage(
		Header{Version: ProtocolVersion, MsgType: 0xfe, TxID: tx},
		&BodyPing{Address: addr[:]},
		priv,
	)
	if err != ErrUnknownMsgType {
		t.Fatalf("got %v", err)
	}
	// decode side: craft minimal invalid outer — use wrong body for type
	hdr := Header{Version: ProtocolVersion, MsgType: 0xfe, TxID: tx}
	body := &BodyPing{Address: addr[:]}
	hcb, _ := canonical.Marshal(hdr)
	bcb, _ := canonical.Marshal(body)
	sig := acrypto.SignDetached(priv, signPayload(hcb, bcb))
	outer := wireOuter{Header: hdr, Body: bcb, SenderPubkey: pub, Signature: sig}
	raw, _ := canonical.Marshal(outer)
	if _, err := VerifyAndDecode(raw); err != ErrUnknownMsgType {
		t.Fatalf("got %v want ErrUnknownMsgType", err)
	}
}

func TestCanonicalDeterminism(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	hdr := Header{Version: ProtocolVersion, MsgType: MsgStoreResp, TxID: tx}
	body := &BodyStoreResp{Stored: true}
	a, _ := MarshalSignedMessage(hdr, body, priv)
	b, _ := MarshalSignedMessage(hdr, body, priv)
	if !bytes.Equal(a, b) {
		t.Fatal("non-deterministic encoding")
	}
	_, err := VerifyAndDecode(a)
	if err != nil {
		t.Fatal(err)
	}
}
