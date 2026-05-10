// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	tunnelCertFile = "tunnel-cert.pem"
	tunnelKeyFile  = "tunnel-key.pem"
)

// loadOrCreateTunnelTLS returns a *tls.Config backed by a self-signed
// certificate covering 127.0.0.1, ::1, and localhost.
//
// The certificate is persisted to dataDir so that the browser only needs to
// accept the security warning once for the cert's lifetime (10 years).
// A new certificate is generated only when none exists or the stored one has
// expired.
func loadOrCreateTunnelTLS(dataDir string) (*tls.Config, error) {
	certPath := filepath.Join(dataDir, tunnelCertFile)
	keyPath := filepath.Join(dataDir, tunnelKeyFile)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if x509c, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Now().Before(x509c.NotAfter) {
				return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
			}
		}
	}

	// Generate new ECDSA P-256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "a2al local tunnel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("tunnel tls: write cert: %w", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("tunnel tls: write key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tunnel tls: parse cert: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

// peekConn wraps a net.Conn so that bytes already consumed into a bufio.Reader
// are replayed on subsequent Read calls. Used for protocol sniffing without
// discarding the peeked bytes.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// sniffAndUpgrade peeks at the first byte of conn. If it is 0x16 (TLS
// ClientHello) and cfg is non-nil, the connection is wrapped as a TLS server
// stream. Otherwise the connection is returned as-is (plain HTTP).
//
// Either way the returned net.Conn replays the peeked byte correctly, so the
// caller can bridge it without any special framing.
func sniffAndUpgrade(conn net.Conn, cfg *tls.Config) net.Conn {
	br := bufio.NewReaderSize(conn, 1)
	b, err := br.Peek(1)
	pc := &peekConn{Conn: conn, r: br}
	if cfg != nil && err == nil && b[0] == 0x16 {
		return tls.Server(pc, cfg)
	}
	return pc
}
