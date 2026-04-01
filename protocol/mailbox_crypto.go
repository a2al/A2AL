// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"
	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"golang.org/x/crypto/hkdf"
)

func ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	var p edwards25519.Point
	if _, err := p.SetBytes(pub); err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func ed25519PrivateToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(priv.Seed())
	defer acrypto.Wipe(h[:])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return ecdh.X25519().NewPrivateKey(h[:32])
}

func deriveMailboxKey(shared, senderAddr, recipientAddr []byte) ([]byte, error) {
	salt := []byte(mailboxSalt)
	info := make([]byte, 0, len(senderAddr)+len(recipientAddr))
	info = append(info, senderAddr...)
	info = append(info, recipientAddr...)
	r := hkdf.New(sha256.New, shared, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func mailboxEncryptAEAD(recipientPub ed25519.PublicKey, senderAddr, recipientAddr a2al.Address, plaintext []byte) (ephemeralPub, nonce, ciphertext []byte, err error) {
	mont, err := ed25519PublicToX25519(recipientPub)
	if err != nil {
		return nil, nil, nil, err
	}
	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(mont)
	if err != nil {
		return nil, nil, nil, err
	}
	ephemPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	shared, err := ephemPriv.ECDH(peerPub)
	if err != nil {
		return nil, nil, nil, err
	}
	defer acrypto.Wipe(shared)
	key, err := deriveMailboxKey(shared, senderAddr[:], recipientAddr[:])
	if err != nil {
		return nil, nil, nil, err
	}
	defer acrypto.Wipe(key)
	nonce = make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	ephemeralPub = ephemPriv.PublicKey().Bytes()
	return ephemeralPub, nonce, ciphertext, nil
}

func mailboxDecryptAEAD(recipientPriv ed25519.PrivateKey, recipientAddr a2al.Address, senderAddr, ephemeralPub, nonce, ciphertext []byte) ([]byte, error) {
	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, err
	}
	xPriv, err := ed25519PrivateToX25519(recipientPriv)
	if err != nil {
		return nil, err
	}
	shared, err := xPriv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	defer acrypto.Wipe(shared)
	key, err := deriveMailboxKey(shared, senderAddr, recipientAddr[:])
	if err != nil {
		return nil, err
	}
	defer acrypto.Wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
