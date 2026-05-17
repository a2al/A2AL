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

// BuildMailboxSignedRecord encrypts and signs a mailbox message for recipient,
// returning the SignedRecord without publishing it to the DHT.
// Use PublishMailboxRecord to store it, or SendMailboxForAgent for the combined path.
func (h *Host) BuildMailboxSignedRecord(ctx context.Context, agentAddr, recipient a2al.Address, msgType uint8, body []byte) (protocol.SignedRecord, error) {
	if h == nil || h.node == nil {
		return protocol.SignedRecord{}, errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return protocol.SignedRecord{}, fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}

	now := time.Now()

	// Fast path: cached recipient pubkey from a prior mailbox exchange.
	var recipientPub ed25519.PublicKey
	if v, ok := h.peerPubkeys.Load(recipient); ok {
		recipientPub = v.(ed25519.PublicKey)
	}

	if len(recipientPub) != ed25519.PublicKeySize {
		recs, err := h.FindRecords(ctx, recipient, protocol.RecTypeEndpoint)
		if err != nil {
			return protocol.SignedRecord{}, fmt.Errorf("a2al/host: recipient endpoint: %w", err)
		}
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
	}

	if len(recipientPub) != ed25519.PublicKeySize {
		return protocol.SignedRecord{}, errors.New("a2al/host: no valid endpoint for recipient")
	}
	payload, err := protocol.EncodeMailboxPayload(agentAddr, recipient, recipientPub, msgType, body)
	if err != nil {
		return protocol.SignedRecord{}, err
	}
	seq := uint64(now.UnixNano())
	ts := uint64(now.Unix())
	var rec protocol.SignedRecord
	if len(ag.delegationCBOR) > 0 {
		rec, err = protocol.SignRecordDelegated(ag.priv, ag.delegationCBOR, agentAddr, protocol.RecTypeMailbox, payload, seq, ts, protocol.DefaultMailboxTTL)
	} else {
		rec, err = protocol.SignRecord(ag.priv, agentAddr, protocol.RecTypeMailbox, payload, seq, ts, protocol.DefaultMailboxTTL)
	}
	return rec, err
}

// PublishMailboxRecord stores a pre-built SignedRecord to the DHT under recipient's key.
func (h *Host) PublishMailboxRecord(ctx context.Context, recipient a2al.Address, rec protocol.SignedRecord) error {
	if h == nil || h.node == nil {
		return errors.New("a2al/host: nil host")
	}
	return h.node.PublishMailboxRecord(ctx, a2al.NodeIDFromAddress(recipient), rec)
}

// SendMailboxForAgent encrypts and stores a mailbox record signed by the given registered agent.
// Delegated agents use SignRecordDelegated (same authority model as PublishEndpointForAgent).
// For direct delivery (QUIC), use BuildMailboxSignedRecord + the daemon's three-tier path.
func (h *Host) SendMailboxForAgent(ctx context.Context, agentAddr, recipient a2al.Address, msgType uint8, body []byte) error {
	rec, err := h.BuildMailboxSignedRecord(ctx, agentAddr, recipient, msgType, body)
	if err != nil {
		return err
	}
	return h.PublishMailboxRecord(ctx, recipient, rec)
}

// PollMailbox aggregates mailbox records for the host default AID (spec §4.4–4.6).
func (h *Host) PollMailbox(ctx context.Context) ([]protocol.MailboxMessage, error) {
	return h.PollMailboxForAgent(ctx, h.addr)
}

// FetchMailboxRawForAgent returns raw verified SignedRecords for agentAddr without
// decrypting them. The caller is responsible for decryption and deduplication.
// This is the low-level counterpart to PollMailboxForAgent used by the daemon's
// persistent mailbox store.
func (h *Host) FetchMailboxRawForAgent(ctx context.Context, agentAddr a2al.Address) ([]protocol.SignedRecord, error) {
	if h == nil || h.node == nil {
		return nil, errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	_, ok := h.agents[agentAddr]
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
	out := make([]protocol.SignedRecord, 0, len(recs))
	for _, sr := range recs {
		if err := protocol.VerifySignedRecord(sr, now); err != nil {
			continue
		}
		out = append(out, sr)
	}
	return out, nil
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
		// Cache the sender's verified public key so future replies to this
		// peer can skip the DHT endpoint lookup in SendMailboxForAgent.
		if len(msg.SenderPubkey) == ed25519.PublicKeySize {
			h.peerPubkeys.Store(msg.Sender, msg.SenderPubkey)
		}
		out = append(out, msg)
	}
	return out, nil
}

// DecryptMailboxRecordFor decrypts a single verified SignedRecord for agentAddr.
func (h *Host) DecryptMailboxRecordFor(agentAddr a2al.Address, sr protocol.SignedRecord) (protocol.MailboxMessage, error) {
	var zero protocol.MailboxMessage
	if h == nil || h.node == nil {
		return zero, errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return zero, fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	msg, err := protocol.OpenMailboxRecord(ag.priv, agentAddr, sr)
	if err != nil {
		return zero, err
	}
	if len(msg.SenderPubkey) == ed25519.PublicKeySize {
		h.peerPubkeys.Store(msg.Sender, msg.SenderPubkey)
	}
	return msg, nil
}

// DecryptMailboxRecords decrypts the given raw SignedRecords using the private
// key of agentAddr. Callers that obtained records from an out-of-band source
// (e.g. fallback infrastructure) can use this to reuse the standard decryption
// path without triggering a DHT query.
func (h *Host) DecryptMailboxRecords(agentAddr a2al.Address, recs []protocol.SignedRecord) ([]protocol.MailboxMessage, error) {
	if h == nil || h.node == nil {
		return nil, errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
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
		if len(msg.SenderPubkey) == ed25519.PublicKeySize {
			h.peerPubkeys.Store(msg.Sender, msg.SenderPubkey)
		}
		out = append(out, msg)
	}
	return out, nil
}
