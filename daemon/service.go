// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/identity"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func (d *Daemon) execIdentityGenerate() (identityGenResp, error) {
	mPub, mPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return identityGenResp{}, err
	}
	oPub, oPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return identityGenResp{}, err
	}
	aid, err := crypto.AddressFromPublicKey(mPub)
	if err != nil {
		return identityGenResp{}, err
	}
	now := uint64(time.Now().Unix())
	proof, err := identity.SignDelegation(mPriv, oPub, aid, now, 0, identity.ScopeNetworkOps)
	if err != nil {
		return identityGenResp{}, err
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return identityGenResp{}, err
	}
	return identityGenResp{
		MasterPrivateKeyHex:      hex.EncodeToString(mPriv),
		OperationalPrivateKeyHex: hex.EncodeToString(oPriv),
		DelegationProofHex:       hex.EncodeToString(raw),
		AID:                      aid.String(),
		Warning:                  "Persist master_private_key_hex securely; the daemon does not retain it. Loss = loss of AID ownership.",
	}, nil
}

type ethereumGenResp struct {
	EthereumPrivateKeyHex    string `json:"ethereum_private_key_hex"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
	Warning                  string `json:"warning"`
}

func (d *Daemon) execEthereumIdentityGenerate() (ethereumGenResp, error) {
	ethPriv, opPriv, proof, err := identity.GenerateEthereumIdentity()
	if err != nil {
		return ethereumGenResp{}, err
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return ethereumGenResp{}, err
	}
	aid, err := proof.AgentAID()
	if err != nil {
		return ethereumGenResp{}, err
	}
	return ethereumGenResp{
		EthereumPrivateKeyHex:    hex.EncodeToString(ethPriv.Serialize()),
		OperationalPrivateKeyHex: hex.EncodeToString(opPriv),
		DelegationProofHex:       hex.EncodeToString(raw),
		AID:                      aid.String(),
		Warning:                  "Persist ethereum_private_key_hex like a wallet seed; the daemon does not retain it. Loss = loss of AID ownership.",
	}, nil
}

type paralismGenResp struct {
	ParalismPrivateKeyHex    string `json:"paralism_private_key_hex"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
	Warning                  string `json:"warning"`
}

func (d *Daemon) execParalismIdentityGenerate() (paralismGenResp, error) {
	btcPriv, opPriv, proof, err := identity.GenerateParalismIdentity()
	if err != nil {
		return paralismGenResp{}, err
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return paralismGenResp{}, err
	}
	aid, err := proof.AgentAID()
	if err != nil {
		return paralismGenResp{}, err
	}
	return paralismGenResp{
		ParalismPrivateKeyHex:    hex.EncodeToString(btcPriv.Serialize()),
		OperationalPrivateKeyHex: hex.EncodeToString(opPriv),
		DelegationProofHex:       hex.EncodeToString(raw),
		AID:                      aid.String(),
		Warning:                  "Persist paralism_private_key_hex like a wallet seed; the daemon does not retain it. Loss = loss of AID ownership.",
	}, nil
}

func (d *Daemon) persistDelegatedAgent(aid a2al.Address, opPriv ed25519.PrivateKey, proofRaw []byte, serviceTCP string) error {
	if aid == d.nodeAddr {
		return errNodeAsAgent
	}
	// service_tcp is optional: agents with their own public URL don't need daemon gateway forwarding.
	// Warn when set but unreachable; do not block registration.
	if serviceTCP != "" && !probeTCP(serviceTCP, 2*time.Second) {
		d.log.Warn("service_tcp unreachable at registration time; daemon gateway forwarding will not work until it becomes reachable", "aid", aid.String(), "service_tcp", serviceTCP)
	}
	if err := d.h.RegisterDelegatedAgent(aid, opPriv, proofRaw); err != nil {
		return err
	}
	ent := &registry.Entry{
		AID:            aid,
		ServiceTCP:     serviceTCP,
		OpPriv:         opPriv,
		DelegationCBOR: proofRaw,
		Seq:            0, // first DHT publish uses seq 1 via POST /publish or auto-republish
	}
	if err := d.reg.Put(ent); err != nil {
		d.h.UnregisterAgent(aid)
		return errPersist
	}
	d.bumpIceRegistry()
	return nil
}

func decodeFlexibleHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

func operationalPrivateFromHexOrSeed(privHex, seedHex string) (ed25519.PrivateKey, error) {
	switch {
	case privHex != "" && seedHex != "":
		return nil, errEthOpKeyAmbiguous
	case privHex != "":
		raw, err := decodeFlexibleHex(privHex)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errBadOpKeyHex
		}
		return ed25519.PrivateKey(raw), nil
	case seedHex != "":
		raw, err := decodeFlexibleHex(seedHex)
		if err != nil || len(raw) != ed25519.SeedSize {
			return nil, errBadOpSeedHex
		}
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, errEthOpKeyMissing
	}
}

// execEthereumDelegationMessage builds the canonical UTF-8 string to pass to wallet personal_sign.
func (d *Daemon) execEthereumDelegationMessage(opPubHex, opSeedHex, agentStr string, issuedAt, expiresAt uint64, scope uint8) (string, error) {
	_ = d
	if scope == 0 {
		scope = identity.ScopeNetworkOps
	}
	var opPub ed25519.PublicKey
	switch {
	case opPubHex != "" && opSeedHex != "":
		return "", errEthOpKeyAmbiguous
	case opSeedHex != "":
		seed, err := decodeFlexibleHex(opSeedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return "", errBadOpSeedHex
		}
		opPriv := ed25519.NewKeyFromSeed(seed)
		opPub = opPriv.Public().(ed25519.PublicKey)
	case opPubHex != "":
		opRaw, err := decodeFlexibleHex(opPubHex)
		if err != nil || len(opRaw) != ed25519.PublicKeySize {
			return "", errBadOpPubHex
		}
		opPub = ed25519.PublicKey(opRaw)
	default:
		return "", errEthPubOrSeedRequired
	}
	aid, err := a2al.ParseAddress(strings.TrimSpace(agentStr))
	if err != nil || aid[0] != a2al.VersionEthereum {
		return "", errEthBadAgent
	}
	return identity.BuildEthereumDelegationMessage(opPub, aid, issuedAt, expiresAt, scope), nil
}

// execEthereumRegister verifies EIP-191 signature over the canonical message and registers the agent.
func (d *Daemon) execEthereumRegister(agentStr string, issuedAt, expiresAt uint64, scope uint8, ethSigHex, serviceTCP, opPrivHex, opSeedHex string) (a2al.Address, error) {
	if scope == 0 {
		scope = identity.ScopeNetworkOps
	}
	opPriv, err := operationalPrivateFromHexOrSeed(opPrivHex, opSeedHex)
	if err != nil {
		return a2al.Address{}, err
	}
	opPub := opPriv.Public().(ed25519.PublicKey)
	aid, err := a2al.ParseAddress(strings.TrimSpace(agentStr))
	if err != nil || aid[0] != a2al.VersionEthereum {
		return a2al.Address{}, errEthBadAgent
	}
	canonical := identity.BuildEthereumDelegationMessage(opPub, aid, issuedAt, expiresAt, scope)
	sig, err := decodeFlexibleHex(ethSigHex)
	if err != nil || len(sig) != 65 {
		return a2al.Address{}, errEthBadSignature
	}
	var addr20 [20]byte
	copy(addr20[:], aid[1:])
	if err := crypto.VerifyEIP191Signature(addr20, canonical, sig); err != nil {
		return a2al.Address{}, errEthSigVerify
	}
	proof, err := identity.ImportBlockchainDelegation(sig, canonical, opPub, aid, issuedAt, expiresAt, scope)
	if err != nil {
		return a2al.Address{}, errEthProofBuild
	}
	now := uint64(time.Now().Unix())
	if err := identity.VerifyDelegation(proof, now, opPriv); err != nil {
		return a2al.Address{}, errDelegationVerify
	}
	proofRaw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return a2al.Address{}, errDelegationParse
	}

	d.regMu.Lock()
	defer d.regMu.Unlock()
	if err := d.persistDelegatedAgent(aid, opPriv, proofRaw, serviceTCP); err != nil {
		return a2al.Address{}, err
	}
	return aid, nil
}

type ethereumProofResp struct {
	AID                      string `json:"aid"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex,omitempty"`
	Warning                  string `json:"warning,omitempty"`
}

// execEthereumProofFromKey signs delegation with a local secp256k1 key (automation / AI on trusted paths only).
func (d *Daemon) execEthereumProofFromKey(ethPrivHex string, issuedAt, expiresAt uint64, scope uint8, opPrivHex, opSeedHex string) (ethereumProofResp, error) {
	_ = d
	if scope == 0 {
		scope = identity.ScopeNetworkOps
	}
	ethRaw, err := decodeFlexibleHex(ethPrivHex)
	if err != nil || len(ethRaw) != 32 {
		return ethereumProofResp{}, errEthBadPrivHex
	}
	ethPriv := secp256k1.PrivKeyFromBytes(ethRaw)

	var opPriv ed25519.PrivateKey
	var generatedOp bool
	if opPrivHex != "" || opSeedHex != "" {
		opPriv, err = operationalPrivateFromHexOrSeed(opPrivHex, opSeedHex)
		if err != nil {
			return ethereumProofResp{}, err
		}
	} else {
		_, opPriv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return ethereumProofResp{}, err
		}
		generatedOp = true
	}
	opPub := opPriv.Public().(ed25519.PublicKey)

	var aid a2al.Address
	aid[0] = a2al.VersionEthereum
	addr20, err := crypto.EthPubKeyToAddress20(ethPriv.PubKey())
	if err != nil {
		return ethereumProofResp{}, err
	}
	copy(aid[1:], addr20[:])

	issued := issuedAt
	if issued == 0 {
		issued = uint64(time.Now().Unix())
	}

	proof, err := identity.SignEthDelegation(ethPriv, opPub, aid, issued, expiresAt, scope)
	if err != nil {
		return ethereumProofResp{}, err
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return ethereumProofResp{}, err
	}
	out := ethereumProofResp{
		AID:                aid.String(),
		DelegationProofHex: hex.EncodeToString(raw),
	}
	if generatedOp {
		out.OperationalPrivateKeyHex = hex.EncodeToString(opPriv)
		out.Warning = "New operational key generated; store operational_private_key_hex before registering."
	}
	return out, nil
}

type paralismProofResp struct {
	AID                      string `json:"aid"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex,omitempty"`
	Warning                  string `json:"warning,omitempty"`
}

// execParalismProofFromKey signs delegation with a local secp256k1 key (automation / trusted paths).
func (d *Daemon) execParalismProofFromKey(btcPrivHex string, issuedAt, expiresAt uint64, scope uint8, opPrivHex, opSeedHex string) (paralismProofResp, error) {
	_ = d
	if scope == 0 {
		scope = identity.ScopeNetworkOps
	}
	btcRaw, err := decodeFlexibleHex(btcPrivHex)
	if err != nil || len(btcRaw) != 32 {
		return paralismProofResp{}, errParalismBadPrivHex
	}
	btcPriv := secp256k1.PrivKeyFromBytes(btcRaw)

	var opPriv ed25519.PrivateKey
	var generatedOp bool
	if opPrivHex != "" || opSeedHex != "" {
		opPriv, err = operationalPrivateFromHexOrSeed(opPrivHex, opSeedHex)
		if err != nil {
			return paralismProofResp{}, err
		}
	} else {
		_, opPriv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return paralismProofResp{}, err
		}
		generatedOp = true
	}
	opPub := opPriv.Public().(ed25519.PublicKey)

	var aid a2al.Address
	aid[0] = a2al.VersionParalism
	addr20, err := crypto.Secp256k1PubKeyToHash160(btcPriv.PubKey(), true)
	if err != nil {
		return paralismProofResp{}, err
	}
	copy(aid[1:], addr20[:])

	issued := issuedAt
	if issued == 0 {
		issued = uint64(time.Now().Unix())
	}

	proof, err := identity.SignParalismDelegation(btcPriv, opPub, aid, issued, expiresAt, scope)
	if err != nil {
		return paralismProofResp{}, err
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		return paralismProofResp{}, err
	}
	out := paralismProofResp{
		AID:                aid.String(),
		DelegationProofHex: hex.EncodeToString(raw),
	}
	if generatedOp {
		out.OperationalPrivateKeyHex = hex.EncodeToString(opPriv)
		out.Warning = "New operational key generated; store operational_private_key_hex before registering."
	}
	return out, nil
}

func (d *Daemon) execAgentRegister(req registerAgentReq) (a2al.Address, error) {
	d.regMu.Lock()
	defer d.regMu.Unlock()
	proofRaw, err := decodeFlexibleHex(req.DelegationProofHex)
	if err != nil {
		return a2al.Address{}, errBadDelegationHex
	}
	proof, err := identity.ParseDelegationProof(proofRaw)
	if err != nil {
		return a2al.Address{}, errDelegationParse
	}
	opPrivBytes, err := decodeFlexibleHex(req.OperationalPrivateKeyHex)
	if err != nil || len(opPrivBytes) != ed25519.PrivateKeySize {
		return a2al.Address{}, errBadOpKeyHex
	}
	opPriv := ed25519.PrivateKey(opPrivBytes)
	now := uint64(time.Now().Unix())
	if err := identity.VerifyDelegation(proof, now, opPriv); err != nil {
		return a2al.Address{}, errDelegationVerify
	}
	aid, err := proof.AgentAID()
	if err != nil {
		return a2al.Address{}, errAID
	}
	if err := d.persistDelegatedAgent(aid, opPriv, proofRaw, req.ServiceTCP); err != nil {
		return a2al.Address{}, err
	}
	return aid, nil
}

func (d *Daemon) execAgentsList() []map[string]any {
	d.regMu.RLock()
	list := d.reg.List()
	d.regMu.RUnlock()

	// Snapshot shared maps under their respective locks to avoid holding both
	// locks simultaneously (deadlock prevention).
	d.heartbeatMu.Lock()
	hbSnap := make(map[a2al.Address]time.Time, len(d.heartbeatAt))
	for k, v := range d.heartbeatAt {
		hbSnap[k] = v
	}
	d.heartbeatMu.Unlock()

	d.publishMetaMu.Lock()
	pubSnap := make(map[a2al.Address]time.Time, len(d.agentLastPublish))
	for k, v := range d.agentLastPublish {
		pubSnap[k] = v
	}
	d.publishMetaMu.Unlock()

	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		var tcpOK any // nil = not configured; bool = probe result
		if e.ServiceTCP != "" {
			tcpOK = probeTCP(e.ServiceTCP, 2*time.Second)
		}
		m := map[string]any{
			"aid":              e.AID.String(),
			"service_tcp":      e.ServiceTCP,
			"seq":              e.Seq,
			"service_tcp_ok":   tcpOK,
			"published_to_dht": e.Seq > 0,
			"services":         e.Services,
		}
		if hbT, ok := hbSnap[e.AID]; ok {
			m["heartbeat_seconds_ago"] = time.Since(hbT).Seconds()
		} else {
			m["heartbeat_seconds_ago"] = nil
		}
		if lastPub := pubSnap[e.AID]; !lastPub.IsZero() {
			m["last_publish_at"] = lastPub.UTC().Format(time.RFC3339)
			m["next_republish_estimate"] = lastPub.Add(republishPeriod).UTC().Format(time.RFC3339)
		} else {
			m["last_publish_at"] = nil
			m["next_republish_estimate"] = nil
		}
		out = append(out, m)
	}
	return out
}

func (d *Daemon) execAgentGet(ctx context.Context, aidStr string) (map[string]any, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return nil, errBadAID
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return nil, errNotFound
	}
	var tcpOK any // nil = not configured; bool = probe result
	if e.ServiceTCP != "" {
		tcpOK = probeTCP(e.ServiceTCP, 2*time.Second)
	}
	out := map[string]any{
		"aid":                  e.AID.String(),
		"service_tcp":          e.ServiceTCP,
		"seq":                  e.Seq,
		"service_tcp_ok":       tcpOK,
		"published_to_dht":     e.Seq > 0,
		"services":             e.Services,
		"published_endpoints":  nil,
		"published_nat_type":   nil,
		"published_record_seq": nil,
	}
	d.heartbeatMu.Lock()
	hbT, hbOK := d.heartbeatAt[e.AID]
	d.heartbeatMu.Unlock()
	if hbOK {
		out["heartbeat_seconds_ago"] = time.Since(hbT).Seconds()
	} else {
		out["heartbeat_seconds_ago"] = nil
	}
	d.publishMetaMu.Lock()
	lastPub := d.agentLastPublish[e.AID]
	d.publishMetaMu.Unlock()
	if !lastPub.IsZero() {
		out["last_publish_at"] = lastPub.UTC().Format(time.RFC3339)
		out["next_republish_estimate"] = lastPub.Add(republishPeriod).UTC().Format(time.RFC3339)
	} else {
		out["last_publish_at"] = nil
		out["next_republish_estimate"] = nil
	}
	if e.Seq > 0 {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		er, err := d.h.Resolve(rctx, aid)
		cancel()
		if err == nil && er != nil {
			out["published_endpoints"] = er.Endpoints
			out["published_nat_type"] = er.NatType
			out["published_record_seq"] = er.Seq
		}
	}
	return out, nil
}

func (d *Daemon) execAgentPublish(ctx context.Context, aidStr string) (uint64, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return 0, errBadAID
	}
	// Allow the node AID itself to be passed to force an immediate node endpoint
	// republish without adding a separate API route.
	if aid == d.nodeAddr {
		if err := d.publishNodeOnce(ctx); err != nil {
			return 0, errPublish
		}
		d.nodePublishMu.Lock()
		seq := d.nodePublishSeq
		d.nodePublishMu.Unlock()
		return seq, nil
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return 0, errNotFound
	}
	// Warn when service_tcp is set but unreachable; still allow publish for agents with their own public URL.
	if e.ServiceTCP != "" && !probeTCP(e.ServiceTCP, 2*time.Second) {
		d.log.Warn("service_tcp unreachable at publish time; daemon gateway forwarding will not work", "aid", aid.String(), "service_tcp", e.ServiceTCP)
	}
	nextSeq := e.Seq + 1
	if err := d.h.PublishEndpointForAgent(ctx, aid, nextSeq, 3600); err != nil {
		// Stale record: DHT peers hold a higher seq (e.g. agent was deleted and
		// re-imported, resetting local seq to 0). Resolve the current network seq
		// and retry once at networkSeq+1 — symmetric to recoverSeqFromNetwork for
		// the node AID.
		if errors.Is(err, dht.ErrStaleRecord) {
			if er, rerr := d.h.Resolve(ctx, aid); rerr == nil && er.Seq >= nextSeq {
				d.log.Info("agent seq recovery: network ahead, retrying",
					"aid", aid.String(), "network_seq", er.Seq, "local_seq", e.Seq)
				nextSeq = er.Seq + 1
				if err2 := d.h.PublishEndpointForAgent(ctx, aid, nextSeq, 3600); err2 != nil {
					d.log.Warn("publish endpoint (retry)", "aid", aid.String(), "err", err2)
					return 0, errPublish
				}
				// Retry succeeded — fall through to persist the updated seq.
				goto persist
			}
		}
		d.log.Warn("publish endpoint", "aid", aid.String(), "err", err)
		return 0, errPublish
	}
persist:
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e = d.reg.Get(aid)
	if e == nil {
		return 0, errNotFound
	}
	e.Seq = nextSeq
	if err := d.reg.Put(e); err != nil {
		return 0, errPersist
	}
	d.recordAgentPublishTime(aid)
	return nextSeq, nil
}

// touchHeartbeat records agent liveness for auto-republish (middleware + explicit heartbeat).
// If the agent's last publish is stale or unknown (e.g. after daemon restart), an immediate
// background republish is triggered so services recover without waiting for the 30-min tick.
func (d *Daemon) touchHeartbeat(aid a2al.Address) {
	d.heartbeatMu.Lock()
	if d.heartbeatAt == nil {
		d.heartbeatAt = make(map[a2al.Address]time.Time)
	}
	d.heartbeatAt[aid] = time.Now()
	d.heartbeatMu.Unlock()

	d.publishMetaMu.Lock()
	lastPub := d.agentLastPublish[aid]
	d.publishMetaMu.Unlock()

	if time.Since(lastPub) > republishPeriod && d.reg != nil {
		d.regMu.RLock()
		e := d.reg.Get(aid)
		d.regMu.RUnlock()
		if e != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				d.tryRepublishAgent(ctx, e)
			}()
		}
	}
}

func (d *Daemon) execAgentHeartbeat(aidStr string) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return errNotFound
	}
	d.touchHeartbeat(aid)
	return nil
}

func (d *Daemon) execStatus() map[string]any {
	d.nodePublishMu.Lock()
	nseq := d.nodePublishSeq
	d.nodePublishMu.Unlock()
	d.publishMetaMu.Lock()
	nlp := d.nodeLastPublish
	d.publishMetaMu.Unlock()
	out := map[string]any{
		"node_aid":             d.nodeAddr.String(),
		"auto_publish":         d.cfg.AutoPublish,
		"node_seq":             nseq,
		"node_published":       nseq > 0,
		"republish_interval_s": int(republishPeriod.Seconds()),
		"endpoint_ttl_s":       int(endpointRecordTTL),
	}
	if !nlp.IsZero() {
		out["node_last_publish_at"] = nlp.UTC().Format(time.RFC3339)
		out["node_next_republish_estimate"] = nlp.Add(republishPeriod).UTC().Format(time.RFC3339)
	} else {
		out["node_last_publish_at"] = nil
		out["node_next_republish_estimate"] = nil
	}
	return out
}

func (d *Daemon) execAgentDelete(aidStr string) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	if aid == d.nodeAddr {
		return errDeleteNode
	}
	d.h.UnregisterAgent(aid)
	if err := d.reg.Delete(aid); err != nil {
		return errPersist
	}
	d.heartbeatMu.Lock()
	delete(d.heartbeatAt, aid)
	d.heartbeatMu.Unlock()
	d.publishMetaMu.Lock()
	delete(d.agentLastPublish, aid)
	d.publishMetaMu.Unlock()
	// Stop background replication probing for this agent's records.
	d.h.Node().RemoveRepSetsForPublisher(a2al.NodeIDFromAddress(aid))
	d.bumpIceRegistry()
	return nil
}

func (d *Daemon) execAgentPatch(aidStr string, req patchAgentReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	opPrivBytes, err := hex.DecodeString(req.OperationalPrivateKeyHex)
	if err != nil || len(opPrivBytes) != ed25519.PrivateKeySize {
		return errBadOpKeyHex
	}
	opPriv := ed25519.PrivateKey(opPrivBytes)
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(aid)
	if e == nil {
		return errNotFound
	}
	if subtle.ConstantTimeCompare(e.OpPriv, opPriv) != 1 {
		return errOpKeyMismatch
	}
	// service_tcp is optional; warn when set but unreachable, do not block.
	if req.ServiceTCP != "" && !probeTCP(req.ServiceTCP, 2*time.Second) {
		d.log.Warn("service_tcp unreachable", "aid", aid.String(), "service_tcp", req.ServiceTCP)
	}
	e.ServiceTCP = req.ServiceTCP
	return d.reg.Put(e)
}

func (d *Daemon) execResolve(ctx context.Context, aidStr string) (map[string]any, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return nil, errBadAID
	}
	er, err := d.h.Resolve(ctx, aid)
	if err != nil {
		return nil, errResolve
	}
	return map[string]any{
		"address":   er.Address.String(),
		"endpoints": er.Endpoints,
		"nat_type":  er.NatType,
		"timestamp": er.Timestamp,
		"seq":       er.Seq,
		"ttl":       er.TTL,
	}, nil
}

func (d *Daemon) execConnect(ctx context.Context, remoteAidStr string, body connectReq) (string, error) {
	remote, err := a2al.ParseAddress(remoteAidStr)
	if err != nil {
		return "", errBadAID
	}
	local, err := d.pickLocalAgent(body)
	if err != nil {
		return "", err
	}
	er, err := d.h.Resolve(ctx, remote)
	if err != nil {
		return "", errResolve
	}
	d.log.Debug("connect resolve",
		"local_aid", local.String(),
		"remote_aid", remote.String(),
		"nat_type", er.NatType,
		"endpoints", len(er.Endpoints),
		"has_signal", er.Signal != "",
	)
	qc, err := d.h.ConnectFromRecordFor(ctx, local, remote, er)
	if err != nil {
		d.log.Warn("connect quic", "remote", remote.String(), "err", err)
		return "", errConnectQUIC
	}
	d.log.Debug("connect quic ok", "local_aid", local.String(), "remote_aid", remote.String())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = qc.CloseWithError(0, "listen failed")
		return "", errListen
	}
	go func() {
		defer qc.CloseWithError(0, "tunnel done")
		defer ln.Close()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
		d.log.Debug("tunnel local listen", "local_aid", local.String(), "remote_aid", remote.String(), "listen", ln.Addr().String(), "accept_timeout", "30s")
		tcpConn, err := ln.Accept()
		if err != nil {
			d.log.Debug("tunnel accept done", "local_aid", local.String(), "remote_aid", remote.String(), "listen", ln.Addr().String(), "err", err)
			return
		}
		qctx, qcancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer qcancel()
		qs, err := qc.OpenStreamSync(qctx)
		if err != nil {
			d.log.Warn("tunnel open stream failed", "local_aid", local.String(), "remote_aid", remote.String(), "err", err)
			_ = tcpConn.Close()
			return
		}
		d.log.Debug("tunnel bridge start", "local_aid", local.String(), "remote_aid", remote.String())
		bridgeTCPQUICStream(qs, tcpConn)
		d.log.Debug("tunnel bridge done", "local_aid", local.String(), "remote_aid", remote.String())
	}()
	return ln.Addr().String(), nil
}

func (d *Daemon) execMailboxSend(ctx context.Context, localAidStr, recipientStr string, msgType uint8, body []byte) error {
	aid, err := a2al.ParseAddress(localAidStr)
	if err != nil {
		return errBadAID
	}
	recipient, err := a2al.ParseAddress(recipientStr)
	if err != nil {
		return errBadAID
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return errNotFound
	}
	return d.h.SendMailboxForAgent(ctx, aid, recipient, msgType, body)
}

func (d *Daemon) execMailboxPoll(ctx context.Context, aidStr string) ([]map[string]any, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return nil, errBadAID
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return nil, errNotFound
	}
	msgs, err := d.h.PollMailboxForAgent(ctx, aid)
	if err != nil {
		return nil, err
	}

	d.mailboxSeenMu.Lock()
	if d.mailboxSeen == nil {
		d.mailboxSeen = make(map[string]map[string]time.Time)
	}
	seen := d.mailboxSeen[aidStr]
	if seen == nil {
		seen = make(map[string]time.Time)
		d.mailboxSeen[aidStr] = seen
	}
	now := time.Now()
	const mailboxSeenTTL = 2 * time.Hour
	for k, t := range seen {
		if now.Sub(t) > mailboxSeenTTL {
			delete(seen, k)
		}
	}
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		key := mailboxMsgKey(m)
		if _, already := seen[key]; already {
			continue
		}
		seen[key] = now
		out = append(out, map[string]any{
			"sender":      m.Sender.String(),
			"msg_type":    m.MsgType,
			"body_base64": base64.StdEncoding.EncodeToString(m.Body),
		})
	}
	d.mailboxSeenMu.Unlock()
	return out, nil
}

func mailboxMsgKey(m protocol.MailboxMessage) string {
	return hex.EncodeToString(m.Sender[:]) + ":" + strconv.FormatUint(m.Seq, 10)
}

type topicRegisterReq struct {
	Services  []string       `json:"services"`
	Name      string         `json:"name"`
	Protocols []string       `json:"protocols"`
	Tags      []string       `json:"tags"`
	Brief     string         `json:"brief"`
	Meta      map[string]any `json:"meta,omitempty"`
	TTL       uint32         `json:"ttl"`
}

type discoverReq struct {
	Services []string                 `json:"services"`
	Filter *protocol.DiscoverFilter `json:"filter,omitempty"`
}

func topicEntryToMap(e protocol.TopicEntry) map[string]any {
	return map[string]any{
		"aid":       e.Address.String(),
		"seq":       e.Seq,
		"timestamp": e.Timestamp,
		"ttl":       e.TTL,
		"version":   e.Version,
		"service":   e.Topic,
		"name":      e.Name,
		"protocols": e.Protocols,
		"tags":      e.Tags,
		"brief":     e.Brief,
		"meta":      e.Meta,
	}
}

func (d *Daemon) execTopicRegister(ctx context.Context, aidStr string, req topicRegisterReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	if len(req.Services) == 0 {
		return errServicesRequired
	}
	base := protocol.TopicPayload{
		Name:      req.Name,
		Protocols: req.Protocols,
		Tags:      req.Tags,
		Brief:     req.Brief,
		Meta:      req.Meta,
	}
	if aid == d.nodeAddr {
		return d.h.RegisterTopicsForAgent(ctx, aid, req.Services, base, req.TTL)
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return errNotFound
	}
	if err := d.h.RegisterTopicsForAgent(ctx, aid, req.Services, base, req.TTL); err != nil {
		return err
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e = d.reg.Get(aid)
	if e == nil {
		return errNotFound
	}
	// Build a map of existing services keyed by topic name for upsert.
	byTopic := make(map[string]registry.ServiceRecord, len(e.Services)+len(req.Services))
	for _, s := range e.Services {
		byTopic[s.Topic] = s
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = 3600
	}
	for _, t := range req.Services {
		byTopic[t] = registry.ServiceRecord{
			Topic:     t,
			Name:      req.Name,
			Protocols: req.Protocols,
			Tags:      req.Tags,
			Brief:     req.Brief,
			Meta:      req.Meta,
			TTL:       ttl,
		}
	}
	next := make([]registry.ServiceRecord, 0, len(byTopic))
	for _, s := range byTopic {
		next = append(next, s)
	}
	slices.SortFunc(next, func(a, b registry.ServiceRecord) int {
		return strings.Compare(a.Topic, b.Topic)
	})
	e.Services = next
	return d.reg.Put(e)
}

func (d *Daemon) execTopicUnregister(aidStr, topic string) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	if aid == d.nodeAddr {
		// Node topics are not tracked in agents.json; DHT TTL handles expiry.
		return nil
	}
	d.regMu.Lock()
	defer d.regMu.Unlock()
	e := d.reg.Get(aid)
	if e == nil {
		return errNotFound
	}
	out := make([]registry.ServiceRecord, 0, len(e.Services))
	for _, s := range e.Services {
		if s.Topic != topic {
			out = append(out, s)
		}
	}
	e.Services = out
	return d.reg.Put(e)
}

func (d *Daemon) execDiscover(ctx context.Context, req discoverReq) ([]map[string]any, error) {
	if len(req.Services) == 0 {
		return nil, errServicesRequired
	}
	var entries []protocol.TopicEntry
	var err error
	if len(req.Services) == 1 {
		entries, err = d.h.SearchTopic(ctx, req.Services[0])
	} else {
		entries, err = d.h.SearchTopics(ctx, req.Services)
	}
	if err != nil {
		return nil, err
	}
	if req.Filter != nil {
		entries = protocol.FilterTopicEntries(entries, req.Filter)
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, topicEntryToMap(e))
	}
	return out, nil
}

type agentPublishRecordReq struct {
	RecType       uint8  `json:"rec_type"`
	PayloadBase64 string `json:"payload_base64"`
	TTL           uint32 `json:"ttl"`
}

func sovereignCustomRecType(t uint8) bool { return t >= 0x02 && t <= 0x0f }

func signedRecordToAPI(sr protocol.SignedRecord) (map[string]any, error) {
	var addr a2al.Address
	if len(sr.Address) != len(addr) {
		return nil, errors.New("bad record address length")
	}
	copy(addr[:], sr.Address)
	m := map[string]any{
		"aid":              addr.String(),
		"rec_type":         sr.RecType,
		"payload_base64":   base64.StdEncoding.EncodeToString(sr.Payload),
		"seq":              sr.Seq,
		"timestamp":        sr.Timestamp,
		"ttl":              sr.TTL,
		"pubkey_base64":    base64.StdEncoding.EncodeToString(sr.Pubkey),
		"signature_base64": base64.StdEncoding.EncodeToString(sr.Signature),
	}
	if len(sr.Delegation) > 0 {
		m["delegation_base64"] = base64.StdEncoding.EncodeToString(sr.Delegation)
	}
	return m, nil
}

func (d *Daemon) execAgentPublishRecord(ctx context.Context, aidStr string, req agentPublishRecordReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	if !sovereignCustomRecType(req.RecType) {
		return errBadRecType
	}
	if req.TTL == 0 {
		return errTTLRequired
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
	if err != nil {
		return errBadPayloadB64
	}
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return errNotFound
	}
	if len(e.DelegationCBOR) == 0 {
		return errNoDelegation
	}
	now := time.Now()
	seq := uint64(now.UnixNano())
	ts := uint64(now.Unix())
	rec, err := protocol.SignRecordDelegated(e.OpPriv, e.DelegationCBOR, aid, req.RecType, payload, seq, ts, req.TTL)
	if err != nil {
		return err
	}
	return d.h.PublishRecord(ctx, rec)
}

func (d *Daemon) execResolveRecords(ctx context.Context, aidStr string, recType uint8) ([]map[string]any, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return nil, errBadAID
	}
	recs, err := d.h.FindRecords(ctx, aid, recType)
	if err != nil {
		if errors.Is(err, dht.ErrNoMatchingRecords) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(recs))
	for _, sr := range recs {
		if err := protocol.VerifySignedRecord(sr, now); err != nil {
			continue
		}
		m, err := signedRecordToAPI(sr)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

var (
	errBadOpPubHex           = errors.New("bad operational_public_key_hex")
	errEthPubOrSeedRequired  = errors.New("operational_public_key_hex or operational_private_key_seed_hex required")
	errBadOpSeedHex          = errors.New("bad operational_private_key_seed_hex")
	errEthOpKeyMissing       = errors.New("operational_private_key_hex or operational_private_key_seed_hex required")
	errEthOpKeyAmbiguous     = errors.New("provide only one of operational_private_key_hex or operational_private_key_seed_hex")
	errEthBadAgent           = errors.New("bad ethereum agent address")
	errEthBadSignature       = errors.New("bad eth_signature_hex (want 65 bytes)")
	errEthSigVerify          = errors.New("ethereum signature verification failed")
	errEthBadPrivHex         = errors.New("bad ethereum_private_key_hex")
	errEthProofBuild         = errors.New("ethereum proof build failed")
	errParalismBadPrivHex    = errors.New("bad paralism_private_key_hex")
	errBadDelegationHex      = errors.New("bad delegation_proof_hex")
	errDelegationParse       = errors.New("delegation parse")
	errBadOpKeyHex           = errors.New("bad operational_private_key_hex")
	errDelegationVerify      = errors.New("delegation verify")
	errAID                   = errors.New("aid")
	errNodeAsAgent = errors.New("cannot register node identity as agent")
	errPersist     = errors.New("persist failed")
	errBadAID                = errors.New("bad aid")
	errNotFound              = errors.New("not found")
	errPublish               = errors.New("publish failed")
	errDeleteNode            = errors.New("cannot delete node identity")
	errResolve               = errors.New("resolve failed")
	errListen                = errors.New("listen failed")
	errConnectQUIC           = errors.New("quic connect failed")
	errOpKeyMismatch         = errors.New("operational key mismatch")
	errServicesRequired      = errors.New("services required")
	errBadRecType            = errors.New("rec_type must be sovereign custom 0x02-0x0f")
	errTTLRequired           = errors.New("ttl required")
	errBadPayloadB64         = errors.New("invalid payload_base64")
	errNoDelegation          = errors.New("delegation required")
)
