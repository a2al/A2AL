// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/identity"
	"github.com/fxamacker/cbor/v2"
)

const ALPNQuic = "a2al-quic-1"

var (
	errNoLeafCert   = errors.New("a2al/host: no leaf certificate")
	errNotEd25519   = errors.New("a2al/host: certificate is not Ed25519")
	errPeerMismatch = errors.New("a2al/host: peer certificate does not match expected address")

	// oidA2ALDelegation is the custom X.509 extension OID that embeds
	// a DelegationProof in a TLS certificate signed by an operational key.
	oidA2ALDelegation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 999999, 1}
)

// tlsDelegationExt is the CBOR payload of the oidA2ALDelegation extension.
type tlsDelegationExt struct {
	AgentAddr []byte `cbor:"1,keyasint"` // 21-byte AID
	Proof     []byte `cbor:"2,keyasint"` // CBOR-encoded DelegationProof
}

// verifyPeerEd25519 checks that a raw certificate chain contains a single
// Ed25519 leaf whose public key derives to a valid AID. If expectAddr is
// non-zero, the derived AID must match it exactly.
// For Phase 3 delegated agents, the cert contains an oidA2ALDelegation extension
// carrying the AID and a DelegationProof; these are verified as fallback when
// the cert's signing key does not directly derive expectAddr.
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
	if expectAddr == (a2al.Address{}) || addr == expectAddr {
		return addr, nil
	}
	// Delegation fallback: look for the a2al delegation extension.
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidA2ALDelegation) {
			continue
		}
		var extCBOR []byte
		if _, err := asn1.Unmarshal(ext.Value, &extCBOR); err != nil {
			return a2al.Address{}, fmt.Errorf("%w: delegation ext: %v", errPeerMismatch, err)
		}
		var de tlsDelegationExt
		if err := cbor.Unmarshal(extCBOR, &de); err != nil {
			return a2al.Address{}, fmt.Errorf("%w: delegation ext cbor: %v", errPeerMismatch, err)
		}
		if len(de.AgentAddr) != len(a2al.Address{}) {
			return a2al.Address{}, fmt.Errorf("%w: delegation ext agent addr length", errPeerMismatch)
		}
		var agentAID a2al.Address
		copy(agentAID[:], de.AgentAddr)
		if agentAID != expectAddr {
			return a2al.Address{}, fmt.Errorf("%w: got %s, want %s", errPeerMismatch, agentAID, expectAddr)
		}
		proof, err := identity.ParseDelegationProof(de.Proof)
		if err != nil {
			return a2al.Address{}, fmt.Errorf("%w: delegation proof: %v", errPeerMismatch, err)
		}
		if !bytes.Equal(proof.OpPub, pub) {
			return a2al.Address{}, fmt.Errorf("%w: delegation op key", errPeerMismatch)
		}
		if err := identity.VerifyDelegation(proof, uint64(time.Now().Unix()), nil); err != nil {
			return a2al.Address{}, fmt.Errorf("%w: delegation: %v", errPeerMismatch, err)
		}
		return agentAID, nil
	}
	return a2al.Address{}, fmt.Errorf("%w: got %s, want %s", errPeerMismatch, addr, expectAddr)
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

// quicClientTLSWithCert returns a TLS config for dialing a specific remote agent.
// The client presents the provided certificate (mutual TLS) and verifies the
// server's certificate matches expectRemote.
func quicClientTLSWithCert(cert tls.Certificate, expectRemote a2al.Address) (*tls.Config, error) {
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
	return buildEd25519Cert(priv, nil)
}

// selfSignedEd25519CertDelegated creates a self-signed cert for opPriv that
// embeds the AID and DelegationProof in a custom X.509 extension so that
// remote peers can verify the operational key's authority for the AID.
func selfSignedEd25519CertDelegated(opPriv ed25519.PrivateKey, agentAID a2al.Address, delegationCBOR []byte) (tls.Certificate, error) {
	extCBOR, err := cbor.Marshal(tlsDelegationExt{
		AgentAddr: agentAID[:],
		Proof:     delegationCBOR,
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	extDER, err := asn1.Marshal(extCBOR)
	if err != nil {
		return tls.Certificate{}, err
	}
	return buildEd25519Cert(opPriv, []pkix.Extension{{Id: oidA2ALDelegation, Value: extDER}})
}

func buildEd25519Cert(priv ed25519.PrivateKey, extraExts []pkix.Extension) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber:    sn,
		Subject:         pkix.Name{Organization: []string{"a2al"}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: extraExts,
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
// TLS state (works after mutual TLS handshake). For Phase 3 delegated agents,
// it returns the AID from the delegation extension rather than the op-key-derived address.
func PeerAddressFromConn(tlsPeerCerts []*x509.Certificate) (a2al.Address, error) {
	if len(tlsPeerCerts) == 0 {
		return a2al.Address{}, errNoLeafCert
	}
	cert := tlsPeerCerts[0]
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return a2al.Address{}, errNotEd25519
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidA2ALDelegation) {
			continue
		}
		var extCBOR []byte
		if _, err := asn1.Unmarshal(ext.Value, &extCBOR); err != nil {
			break
		}
		var de tlsDelegationExt
		if err := cbor.Unmarshal(extCBOR, &de); err != nil || len(de.AgentAddr) != len(a2al.Address{}) {
			break
		}
		var addr a2al.Address
		copy(addr[:], de.AgentAddr)
		return addr, nil
	}
	return crypto.AddressFromPublicKey(pub)
}
