// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package envelope provides PBKDF2-SHA256 + AES-256-GCM password-based
// encryption in a versioned JSON format compatible with the Web UI crypto.js.
//
// Empty password is accepted and produces a valid envelope — callers that want
// to skip encryption should check the password before calling Seal.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	version    = 1
	iterations = 600_000
	keyLen     = 32 // AES-256
	saltLen    = 16
	ivLen      = 12
)

// envelope is the JSON representation — identical to Web UI crypto.js format.
type envelope struct {
	V    int    `json:"v"`
	KDF  string `json:"kdf"`
	Iter int    `json:"iter"`
	Salt string `json:"salt"`
	IV   string `json:"iv"`
	Data string `json:"data"`
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)
}

// Seal encrypts plaintext with password and returns a JSON envelope string.
func Seal(plaintext []byte, password string) (string, error) {
	salt := make([]byte, saltLen)
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	enc := base64.StdEncoding.EncodeToString
	e := envelope{
		V:    version,
		KDF:  "pbkdf2-sha256",
		Iter: iterations,
		Salt: enc(salt),
		IV:   enc(iv),
		Data: enc(ciphertext),
	}
	b, err := json.Marshal(e)
	return string(b), err
}

// Open decrypts a JSON envelope string. Returns ErrWrongPassword when the
// password is incorrect (AES-GCM authentication failure).
func Open(envelopeJSON string, password string) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal([]byte(envelopeJSON), &e); err != nil {
		return nil, err
	}
	if e.V != version {
		return nil, errors.New("envelope: unsupported version")
	}
	dec := func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
	salt, err := dec(e.Salt)
	if err != nil {
		return nil, err
	}
	iv, err := dec(e.IV)
	if err != nil {
		return nil, err
	}
	data, err := dec(e.Data)
	if err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plain, nil
}

// ErrWrongPassword is returned by Open when decryption fails due to a bad password.
var ErrWrongPassword = errors.New("envelope: wrong password")

// IsEnvelope reports whether s looks like a sealed envelope JSON.
func IsEnvelope(s string) bool {
	if len(s) == 0 || s[0] != '{' {
		return false
	}
	var e envelope
	return json.Unmarshal([]byte(s), &e) == nil && e.V == version && e.Data != ""
}
