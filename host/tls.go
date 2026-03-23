// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

// ALPNQuic is the negotiated ALPN for A2AL QUIC (Phase 2a).
const ALPNQuic = "a2al-quic-1"

var (
	errNoLeafCert   = errors.New("a2al/host: no leaf certificate")
	errNotEd25519   = errors.New("a2al/host: certificate is not Ed25519")
	errPeerMismatch = errors.New("a2al/host: peer certificate does not match expected address")
)

func quicServerTLS(priv ed25519.PrivateKey) (*tls.Config, error) {
	cert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		return nil, err
	}
	// Phase 2a: one-way TLS (client verifies server AID). Mutual Ed25519 client certs with
	// crypto/tls require a shared CA or InsecureSkipVerify paths that differ per Go version;
	// TODO: full mutual verification (spec Phase 2a) via custom CA pool or VerifyPeerCertificate ordering.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPNQuic},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
	}, nil
}

func quicClientTLS(priv ed25519.PrivateKey, expectRemote a2al.Address) (*tls.Config, error) {
	_ = priv // reserved for mutual-TLS client certificate (Phase 2a uses server-auth only)
	return &tls.Config{
		NextProtos:         []string{ALPNQuic},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		// Verify after handshake: PeerCertificates are populated for QUIC (TLS 1.3).
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 1 {
				return errNoLeafCert
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pub, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok || len(pub) != ed25519.PublicKeySize {
				return errNotEd25519
			}
			addr, err := crypto.AddressFromPublicKey(pub)
			if err != nil {
				return err
			}
			if addr != expectRemote {
				return fmt.Errorf("%w", errPeerMismatch)
			}
			return nil
		},
	}, nil
}

func selfSignedEd25519Cert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"a2al"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
