// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/a2al/a2al"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	encryptedBlobMagic   = "a2al-k1"
	saltSize             = 16
	xchachaNonceSize     = chacha20poly1305.NonceSizeX
	argonTime            = 3
	argonMemoryKiB       = 64 * 1024
	argonThreads         = 4
	deriveKeyLen         = 32
	ed25519SeedSize      = ed25519.SeedSize
	defaultIdentityStore = "identity.ed25519"
)

var (
	// ErrIdentityExists is returned when Generate is called but a key is already loaded.
	ErrIdentityExists = errors.New("a2al/crypto: identity already exists")
	// ErrNoIdentity is returned when signing is requested before Load or Generate.
	ErrNoIdentity = errors.New("a2al/crypto: no identity loaded")
	// ErrWrongPassphrase is returned when the ciphertext cannot be authenticated.
	ErrWrongPassphrase = errors.New("a2al/crypto: wrong passphrase or corrupted blob")
)

// EncryptedKeyStore stores a single Ed25519 identity in a2al.Storage as an Argon2id +
// XChaCha20-Poly1305 encrypted blob. Passphrase is required to encrypt/decrypt.
type EncryptedKeyStore struct {
	stg     a2al.Storage
	blobKey string
	pass    []byte

	mu   sync.Mutex
	priv ed25519.PrivateKey // nil if not loaded
}

// NewEncryptedKeyStore creates a keystore. blobKey is the Storage key (e.g.
// "identity.ed25519"); if empty, defaultIdentityStore is used.
func NewEncryptedKeyStore(stg a2al.Storage, blobKey string, passphrase []byte) *EncryptedKeyStore {
	if blobKey == "" {
		blobKey = defaultIdentityStore
	}
	return &EncryptedKeyStore{stg: stg, blobKey: blobKey, pass: passphrase}
}

// Load reads and decrypts the identity from Storage. Missing blob leaves the store empty (no error).
func (e *EncryptedKeyStore) Load() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.priv != nil {
		return nil
	}
	ciphertext, err := e.stg.Get(e.blobKey)
	if errors.Is(err, a2al.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	priv, err := decryptIdentity(e.pass, ciphertext)
	if err != nil {
		return err
	}
	e.priv = priv
	return nil
}

// Generate creates a new Ed25519 identity and encrypts it to Storage.
// Fails with ErrIdentityExists if a key is already in memory.
func (e *EncryptedKeyStore) Generate(keyType KeyType) (PrivateKey, error) {
	if keyType != KeyTypeEd25519 {
		return nil, fmt.Errorf("a2al/crypto: unsupported key type %d", keyType)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.priv != nil {
		return nil, ErrIdentityExists
	}
	if _, err := e.stg.Get(e.blobKey); err == nil {
		return nil, ErrIdentityExists
	} else if !errors.Is(err, a2al.ErrNotFound) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ct, err := encryptIdentity(e.pass, priv.Seed())
	if err != nil {
		return nil, err
	}
	if err := e.stg.Put(e.blobKey, ct); err != nil {
		return nil, err
	}
	e.priv = priv
	out := make(PrivateKey, len(priv))
	copy(out, priv)
	return out, nil
}

// Sign implements KeyStore.
func (e *EncryptedKeyStore) Sign(address a2al.Address, data []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.priv == nil {
		return nil, ErrNoIdentity
	}
	want, err := AddressFromPublicKey(e.priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if want != address {
		return nil, errors.New("a2al/crypto: address does not match loaded key")
	}
	return ed25519.Sign(e.priv, data), nil
}

// PublicKey implements KeyStore.
func (e *EncryptedKeyStore) PublicKey(address a2al.Address) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.priv == nil {
		return nil, ErrNoIdentity
	}
	pub := e.priv.Public().(ed25519.PublicKey)
	want, err := AddressFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if want != address {
		return nil, errors.New("a2al/crypto: address does not match loaded key")
	}
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

// List implements KeyStore.
func (e *EncryptedKeyStore) List() ([]a2al.Address, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.priv == nil {
		return nil, nil
	}
	a, err := AddressFromPublicKey(e.priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return []a2al.Address{a}, nil
}

func encryptIdentity(pass, seed []byte) ([]byte, error) {
	if len(seed) != ed25519SeedSize {
		return nil, errors.New("a2al/crypto: invalid seed length")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(pass, salt, argonTime, argonMemoryKiB, argonThreads, deriveKeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, xchachaNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, seed, nil)
	out := make([]byte, 0, len(encryptedBlobMagic)+saltSize+xchachaNonceSize+len(ct))
	out = append(out, encryptedBlobMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func decryptIdentity(pass, blob []byte) (ed25519.PrivateKey, error) {
	minLen := len(encryptedBlobMagic) + saltSize + xchachaNonceSize + ed25519SeedSize + 16 // + poly1305 tag
	if len(blob) < minLen {
		return nil, ErrWrongPassphrase
	}
	if string(blob[:len(encryptedBlobMagic)]) != encryptedBlobMagic {
		return nil, ErrWrongPassphrase
	}
	salt := blob[len(encryptedBlobMagic) : len(encryptedBlobMagic)+saltSize]
	nonce := blob[len(encryptedBlobMagic)+saltSize : len(encryptedBlobMagic)+saltSize+xchachaNonceSize]
	ct := blob[len(encryptedBlobMagic)+saltSize+xchachaNonceSize:]
	key := argon2.IDKey(pass, salt, argonTime, argonMemoryKiB, argonThreads, deriveKeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	if len(seed) != ed25519SeedSize {
		return nil, ErrWrongPassphrase
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
