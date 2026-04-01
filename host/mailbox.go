// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
)

// SendMailbox encrypts a message for recipient using the host default identity (spec §4.4–4.6).
func (h *Host) SendMailbox(ctx context.Context, recipient a2al.Address, msgType uint8, body []byte) error {
	return h.SendMailboxForAgent(ctx, h.addr, recipient, msgType, body)
}

// SendMailboxForAgent encrypts and stores a mailbox record signed by the given registered agent.
// Delegated agents use SignRecordDelegated (same authority model as PublishEndpointForAgent).
func (h *Host) SendMailboxForAgent(ctx context.Context, agentAddr, recipient a2al.Address, msgType uint8, body []byte) error {
	if h == nil || h.node == nil {
		return errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	recs, err := h.FindRecords(ctx, recipient, protocol.RecTypeEndpoint)
	if err != nil {
		return fmt.Errorf("a2al/host: recipient endpoint: %w", err)
	}
	now := time.Now()
	var recipientPub ed25519.PublicKey
	for _, r := range recs {
		if r.RecType != protocol.RecTypeEndpoint {
			continue
		}
		if err := protocol.VerifySignedRecord(r, now); err != nil {
			continue
		}
		recipientPub = append(ed25519.PublicKey(nil), r.Pubkey...)
		break
	}
	if len(recipientPub) != ed25519.PublicKeySize {
		return errors.New("a2al/host: no valid endpoint for recipient")
	}
	payload, err := protocol.EncodeMailboxPayload(agentAddr, recipient, recipientPub, msgType, body)
	if err != nil {
		return err
	}
	seq := uint64(now.UnixNano())
	ts := uint64(now.Unix())
	var rec protocol.SignedRecord
	if len(ag.delegationCBOR) > 0 {
		rec, err = protocol.SignRecordDelegated(ag.priv, ag.delegationCBOR, agentAddr, protocol.RecTypeMailbox, payload, seq, ts, protocol.DefaultMailboxTTL)
	} else {
		rec, err = protocol.SignRecord(ag.priv, agentAddr, protocol.RecTypeMailbox, payload, seq, ts, protocol.DefaultMailboxTTL)
	}
	if err != nil {
		return err
	}
	return h.node.PublishMailboxRecord(ctx, a2al.NodeIDFromAddress(recipient), rec)
}

// PollMailbox aggregates mailbox records for the host default AID (spec §4.4–4.6).
func (h *Host) PollMailbox(ctx context.Context) ([]protocol.MailboxMessage, error) {
	return h.PollMailboxForAgent(ctx, h.addr)
}

// PollMailboxForAgent aggregates and decrypts mailbox records for agentAddr.
func (h *Host) PollMailboxForAgent(ctx context.Context, agentAddr a2al.Address) ([]protocol.MailboxMessage, error) {
	if h == nil || h.node == nil {
		return nil, errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	q := dht.NewQuery(h.node)
	key := a2al.NodeIDFromAddress(agentAddr)
	recs, err := q.AggregateRecords(ctx, key, protocol.RecTypeMailbox)
	if err != nil {
		if errors.Is(err, dht.ErrNoMatchingRecords) {
			return nil, nil
		}
		return nil, err
	}
	now := time.Now()
	var out []protocol.MailboxMessage
	for _, sr := range recs {
		if err := protocol.VerifySignedRecord(sr, now); err != nil {
			continue
		}
		msg, err := protocol.OpenMailboxRecord(ag.priv, agentAddr, sr)
		if err != nil {
			continue
		}
		out = append(out, msg)
	}
	return out, nil
}
