// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/identity"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

// newTestAgent registers a fresh delegated agent in d and returns its AID.
func newTestAgent(t *testing.T, d *Daemon) a2al.Address {
	t.Helper()
	mPub, mPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oPub, oPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(mPub)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignDelegation(mPriv, oPub, aid, uint64(time.Now().Unix()), 0, identity.ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := identity.EncodeDelegationProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.reg.Put(&registry.Entry{
		AID: aid, OpPriv: oPriv, DelegationCBOR: raw, Seq: 0, ServiceTCP: "",
	}); err != nil {
		t.Fatal(err)
	}
	return aid
}

func TestExecAgentPublish_recoverStaleSeq(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)

	var publishCalls int
	d.testPublishEndpointForAgent = func(_ context.Context, _ a2al.Address, seq uint64, _ uint32) error {
		publishCalls++
		switch seq {
		case 1:
			return dht.ErrStaleRecord
		case 6:
			return nil
		default:
			t.Errorf("unexpected seq=%d (call #%d)", seq, publishCalls)
			return nil
		}
	}
	d.testResolveEndpoint = func(_ context.Context, target a2al.Address) (*protocol.EndpointRecord, error) {
		if target != aid {
			t.Errorf("resolve target %v want %v", target, aid)
		}
		return &protocol.EndpointRecord{Seq: 5}, nil
	}
	defer func() { d.testPublishEndpointForAgent = nil; d.testResolveEndpoint = nil }()

	gotSeq, err := d.execAgentPublish(context.Background(), aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if gotSeq != 6 {
		t.Fatalf("seq=%d want 6", gotSeq)
	}
	if publishCalls != 2 {
		t.Fatalf("publishCalls=%d want 2", publishCalls)
	}
	if e := d.reg.Get(aid); e == nil || e.Seq != 6 {
		t.Fatalf("registry entry seq=%v", e)
	}
}

func TestExecAgentPublish_staleSeq_resolveTooLow(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)

	d.testPublishEndpointForAgent = func(context.Context, a2al.Address, uint64, uint32) error {
		return dht.ErrStaleRecord
	}
	d.testResolveEndpoint = func(context.Context, a2al.Address) (*protocol.EndpointRecord, error) {
		return &protocol.EndpointRecord{Seq: 0}, nil // seq 0 < nextSeq 1, no recovery
	}
	defer func() { d.testPublishEndpointForAgent = nil; d.testResolveEndpoint = nil }()

	_, err := d.execAgentPublish(context.Background(), aid.String())
	if !errors.Is(err, errPublish) {
		t.Fatalf("err=%v want errPublish", err)
	}
}

func TestExecAgentPublish_staleSeq_resolveErr(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)

	d.testPublishEndpointForAgent = func(context.Context, a2al.Address, uint64, uint32) error {
		return dht.ErrStaleRecord
	}
	d.testResolveEndpoint = func(context.Context, a2al.Address) (*protocol.EndpointRecord, error) {
		return nil, errors.New("resolve failed")
	}
	defer func() { d.testPublishEndpointForAgent = nil; d.testResolveEndpoint = nil }()

	_, err := d.execAgentPublish(context.Background(), aid.String())
	if !errors.Is(err, errPublish) {
		t.Fatalf("err=%v want errPublish", err)
	}
}

func TestExecAgentPublish_staleSeq_retryPublishAlsoFails(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)

	var calls int
	d.testPublishEndpointForAgent = func(context.Context, a2al.Address, uint64, uint32) error {
		calls++
		// Both attempts fail: first with ErrStaleRecord, retry with generic error.
		if calls == 1 {
			return dht.ErrStaleRecord
		}
		return errors.New("network error on retry")
	}
	d.testResolveEndpoint = func(context.Context, a2al.Address) (*protocol.EndpointRecord, error) {
		return &protocol.EndpointRecord{Seq: 10}, nil // seq high enough to trigger retry
	}
	defer func() { d.testPublishEndpointForAgent = nil; d.testResolveEndpoint = nil }()

	_, err := d.execAgentPublish(context.Background(), aid.String())
	if !errors.Is(err, errPublish) {
		t.Fatalf("err=%v want errPublish", err)
	}
	if calls != 2 {
		t.Fatalf("publishCalls=%d want 2", calls)
	}
}
