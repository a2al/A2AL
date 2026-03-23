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

const ALPNQuic = "a2al-quic-1"

var (
	errNoLeafCert   = errors.New("a2al/host: no leaf certificate")
	errNotEd25519   = errors.New("a2al/host: certificate is not Ed25519")
	errPeerMismatch = errors.New("a2al/host: peer certificate does not match expected address")
)

// verifyPeerEd25519 checks that a raw certificate chain contains a single
// Ed25519 leaf whose public key derives to a valid AID. If expectAddr is
// non-zero, the derived AID must match it exactly.
func verifyPeerEd25519(rawCerts [][]byte, expectAddr a2al.Address) (a2al.Address, error) {
	if len(rawCerts) == 0 {
		return a2al.Address{}, errNoLeafCert
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return a2al.Address{}, err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return a2al.Address{}, errNotEd25519
	}
	addr, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		return a2al.Address{}, err
	}
	if expectAddr != (a2al.Address{}) && addr != expectAddr {
		return a2al.Address{}, fmt.Errorf("%w: got %s, want %s", errPeerMismatch, addr, expectAddr)
	}
	return addr, nil
}

// quicServerTLS returns a TLS config for the QUIC listener.
// Mutual TLS: server requires a client certificate (RequireAnyClientCert skips
// chain verification for self-signed certs — same pattern as libp2p).
// Both sides verify the peer's Ed25519 public key → AID in VerifyPeerCertificate.
func quicServerTLS(priv ed25519.PrivateKey) (*tls.Config, error) {
	cert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{ALPNQuic},
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := verifyPeerEd25519(rawCerts, a2al.Address{})
			return err
		},
	}, nil
}

// quicServerTLSWithSNI returns a TLS config that selects the server certificate
// dynamically based on TLS SNI (for multi-agent hosting). fallbackCert is used
// when the client sends no SNI or the requested agent is not found.
func quicServerTLSWithSNI(fallbackCert tls.Certificate, getCert func(sni string) *tls.Certificate) *tls.Config {
	return &tls.Config{
		NextProtos:         []string{ALPNQuic},
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				if c := getCert(hello.ServerName); c != nil {
					return c, nil
				}
			}
			return &fallbackCert, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := verifyPeerEd25519(rawCerts, a2al.Address{})
			return err
		},
	}
}

// quicClientTLS returns a TLS config for dialing a specific remote agent.
// The client presents its own self-signed certificate (mutual TLS) and
// verifies the server's certificate matches expectRemote.
func quicClientTLS(priv ed25519.PrivateKey, expectRemote a2al.Address) (*tls.Config, error) {
	cert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ServerName:         expectRemote.String(),
		NextProtos:         []string{ALPNQuic},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := verifyPeerEd25519(rawCerts, expectRemote)
			return err
		},
	}, nil
}

func selfSignedEd25519Cert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: sn,
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

// PeerAddressFromConn extracts the remote peer's AID from a QUIC connection's
// TLS state (works after mutual TLS handshake).
func PeerAddressFromConn(tlsPeerCerts []*x509.Certificate) (a2al.Address, error) {
	if len(tlsPeerCerts) == 0 {
		return a2al.Address{}, errNoLeafCert
	}
	pub, ok := tlsPeerCerts[0].PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return a2al.Address{}, errNotEd25519
	}
	return crypto.AddressFromPublicKey(pub)
}
