package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

type simpleKS struct {
	priv ed25519.PrivateKey
	addr a2al.Address
}

func newSimpleKS() (*simpleKS, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	addr, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &simpleKS{priv: priv, addr: addr}, nil
}

func (s *simpleKS) Generate(crypto.KeyType) (crypto.PrivateKey, error) {
	return nil, errors.New("not supported")
}
func (s *simpleKS) Sign(addr a2al.Address, data []byte) ([]byte, error) {
	if addr != s.addr {
		return nil, errors.New("wrong address")
	}
	return ed25519.Sign(s.priv, data), nil
}
func (s *simpleKS) PublicKey(addr a2al.Address) ([]byte, error) {
	if addr != s.addr {
		return nil, errors.New("wrong address")
	}
	return s.priv.Public().(ed25519.PublicKey), nil
}
func (s *simpleKS) List() ([]a2al.Address, error) {
	return []a2al.Address{s.addr}, nil
}
