package crypto

import (
	"crypto/ed25519"
	"testing"

	"github.com/a2al/a2al"
)

func TestEncryptedKeyStore_roundTrip(t *testing.T) {
	st := a2al.NewMemStorage()
	pass := []byte("test-passphrase-32chars-minimum!!")
	ks := NewEncryptedKeyStore(st, "k1", pass)
	if err := ks.Load(); err != nil {
		t.Fatal(err)
	}
	priv, err := ks.Generate(KeyTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 64 {
		t.Fatalf("priv len %d", len(priv))
	}

	ks2 := NewEncryptedKeyStore(st, "k1", pass)
	if err := ks2.Load(); err != nil {
		t.Fatal(err)
	}
	addrs, err := ks2.List()
	if err != nil || len(addrs) != 1 {
		t.Fatalf("list: %v %v", addrs, err)
	}
	msg := []byte("hello a2al")
	sig, err := ks2.Sign(addrs[0], msg)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ks2.PublicKey(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDetached(pub, msg, sig) {
		t.Fatal("verify failed")
	}
}

func TestEncryptedKeyStore_wrongPassphrase(t *testing.T) {
	st := a2al.NewMemStorage()
	ks := NewEncryptedKeyStore(st, "k1", []byte("correct-horse-battery-staple-phrase"))
	if _, err := ks.Generate(KeyTypeEd25519); err != nil {
		t.Fatal(err)
	}
	ks2 := NewEncryptedKeyStore(st, "k1", []byte("wrong-passphrase----------------"))
	if err := ks2.Load(); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestEncryptedKeyStore_crossSigner(t *testing.T) {
	st := a2al.NewMemStorage()
	pass := []byte("same-passphrase-----------------")
	ks := NewEncryptedKeyStore(st, "k1", pass)
	if _, err := ks.Generate(KeyTypeEd25519); err != nil {
		t.Fatal(err)
	}
	addrs, _ := ks.List()
	msg := []byte("m")
	sig, err := ks.Sign(addrs[0], msg)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if VerifyDetached(otherPub, msg, sig) {
		t.Fatal("wrong key should not verify")
	}
}

func TestEncryptedKeyStore_GenerateTwice(t *testing.T) {
	st := a2al.NewMemStorage()
	pass := []byte("p-------------------------------")
	ks := NewEncryptedKeyStore(st, "k1", pass)
	if _, err := ks.Generate(KeyTypeEd25519); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(KeyTypeEd25519); err != ErrIdentityExists {
		t.Fatalf("got %v want ErrIdentityExists", err)
	}
}

func TestAddressFromPublicKey_consistent(t *testing.T) {
	priv, _, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	a, err := AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := AddressFromPublicKey(ed25519.PublicKey(priv[32:]))
	if err != nil {
		t.Fatal(err)
	}
	if a != a2 {
		t.Fatal("address mismatch")
	}
}

var _ KeyStore = (*EncryptedKeyStore)(nil)
