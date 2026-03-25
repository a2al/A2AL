// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/cmd/a2ald/internal/registry"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/identity"
)

func (d *daemon) execIdentityGenerate() (identityGenResp, error) {
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

func (d *daemon) execAgentRegister(req registerAgentReq) (a2al.Address, error) {
	d.regMu.Lock()
	defer d.regMu.Unlock()
	proofRaw, err := hex.DecodeString(req.DelegationProofHex)
	if err != nil {
		return a2al.Address{}, errBadDelegationHex
	}
	proof, err := identity.ParseDelegationProof(proofRaw)
	if err != nil {
		return a2al.Address{}, errDelegationParse
	}
	opPrivBytes, err := hex.DecodeString(req.OperationalPrivateKeyHex)
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
	if aid == d.nodeAddr {
		return a2al.Address{}, errNodeAsAgent
	}
	if req.ServiceTCP == "" {
		return a2al.Address{}, errServiceTCPRequired
	}
	if !probeTCP(req.ServiceTCP, 2*time.Second) {
		return a2al.Address{}, errServiceTCPUnreachable
	}
	if err := d.h.RegisterDelegatedAgent(aid, opPriv, proofRaw); err != nil {
		return a2al.Address{}, err
	}
	ent := &registry.Entry{
		AID:            aid,
		ServiceTCP:     req.ServiceTCP,
		OpPriv:         opPriv,
		DelegationCBOR: proofRaw,
		Seq:            1,
	}
	if err := d.reg.Put(ent); err != nil {
		d.h.UnregisterAgent(aid)
		return a2al.Address{}, errPersist
	}
	return aid, nil
}

func (d *daemon) execAgentsList() []map[string]any {
	d.regMu.RLock()
	list := d.reg.List()
	d.regMu.RUnlock()
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{
			"aid":         e.AID.String(),
			"service_tcp": e.ServiceTCP,
			"seq":         e.Seq,
		})
	}
	return out
}

func (d *daemon) execAgentGet(ctx context.Context, aidStr string) (map[string]any, error) {
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
	out := map[string]any{
		"aid":                 e.AID.String(),
		"service_tcp":         e.ServiceTCP,
		"seq":                 e.Seq,
		"service_tcp_ok":      probeTCP(e.ServiceTCP, 2*time.Second),
		"published_to_dht":    e.Seq > 1,
		"published_endpoints": nil,
		"published_nat_type":  nil,
		"published_record_seq": nil,
	}
	if e.Seq > 1 {
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

func (d *daemon) execAgentPublish(ctx context.Context, aidStr string) (uint64, error) {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return 0, errBadAID
	}
	// Read current seq under read lock only — do not hold write lock during network IO.
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil {
		return 0, errNotFound
	}
	if !probeTCP(e.ServiceTCP, 2*time.Second) {
		return 0, errServiceTCPUnreachable
	}
	nextSeq := e.Seq + 1
	if err := d.h.PublishEndpointForAgent(ctx, aid, nextSeq, 3600); err != nil {
		d.log.Warn("publish endpoint", "aid", aid.String(), "err", err)
		return 0, errPublish
	}
	// Persist updated seq under write lock.
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
	return nextSeq, nil
}

func (d *daemon) execAgentDelete(aidStr string) error {
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
	return nil
}

// execAgentPatch updates service_tcp after verifying the caller holds the registered operational key.
func (d *daemon) execAgentPatch(aidStr string, req patchAgentReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}
	if req.ServiceTCP == "" {
		return errServiceTCPRequired
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
	if !probeTCP(req.ServiceTCP, 2*time.Second) {
		return errServiceTCPUnreachable
	}
	e.ServiceTCP = req.ServiceTCP
	if err := d.reg.Put(e); err != nil {
		return errPersist
	}
	return nil
}

func (d *daemon) execResolve(ctx context.Context, aidStr string) (map[string]any, error) {
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

func (d *daemon) execConnect(ctx context.Context, remoteAidStr string, body connectReq) (tunnel string, err error) {
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
	qc, err := d.h.ConnectFromRecordFor(ctx, local, remote, er)
	if err != nil {
		d.log.Warn("connect quic", "remote", remote.String(), "err", err)
		return "", errConnectQUIC
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = qc.CloseWithError(0, "listen failed")
		return "", errListen
	}
	go func() {
		defer qc.CloseWithError(0, "tunnel done")
		defer ln.Close()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
		tcpConn, err := ln.Accept()
		if err != nil {
			return
		}
		qctx, qcancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer qcancel()
		qs, err := qc.OpenStreamSync(qctx)
		if err != nil {
			_ = tcpConn.Close()
			return
		}
		bridgeTCPQUICStream(qs, tcpConn)
	}()
	return ln.Addr().String(), nil
}

var (
	errBadDelegationHex      = errors.New("bad delegation_proof_hex")
	errDelegationParse     = errors.New("delegation parse")
	errBadOpKeyHex         = errors.New("bad operational_private_key_hex")
	errDelegationVerify    = errors.New("delegation verify")
	errAID                 = errors.New("aid")
	errNodeAsAgent         = errors.New("cannot register node identity as agent")
	errServiceTCPRequired  = errors.New("service_tcp required")
	errServiceTCPUnreachable = errors.New("service_tcp unreachable")
	errPersist             = errors.New("persist failed")
	errBadAID              = errors.New("bad aid")
	errNotFound            = errors.New("not found")
	errPublish             = errors.New("publish failed")
	errDeleteNode          = errors.New("cannot delete node identity")
	errResolve             = errors.New("resolve failed")
	errListen              = errors.New("listen failed")
	errConnectQUIC         = errors.New("quic connect failed")
	errOpKeyMismatch       = errors.New("operational key mismatch")
)
