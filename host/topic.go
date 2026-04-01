// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
)

const (
	defaultTopicTTL    uint32 = 3600
	maxTopicTTLSeconds uint32 = 7200 // spec §5.9 suggested store cap
)

// RegisterTopic publishes one topic registration for the host default identity (spec §5.7).
func (h *Host) RegisterTopic(ctx context.Context, topic string, entry protocol.TopicPayload, ttl uint32) error {
	return h.RegisterTopicForAgent(ctx, h.addr, topic, entry, ttl)
}

// RegisterTopics registers under multiple topic strings for the default identity (spec §5.7).
func (h *Host) RegisterTopics(ctx context.Context, topics []string, base protocol.TopicPayload, ttl uint32) error {
	return h.RegisterTopicsForAgent(ctx, h.addr, topics, base, ttl)
}

// RegisterTopicsForAgent is RegisterTopics for a registered agent address.
func (h *Host) RegisterTopicsForAgent(ctx context.Context, agentAddr a2al.Address, topics []string, base protocol.TopicPayload, ttl uint32) error {
	for _, t := range topics {
		ent := base
		ent.Topic = t
		if len(base.Meta) > 0 {
			ent.Meta = make(map[string]any, len(base.Meta))
			for k, v := range base.Meta {
				ent.Meta[k] = v
			}
		}
		if err := h.RegisterTopicForAgent(ctx, agentAddr, t, ent, ttl); err != nil {
			return err
		}
	}
	return nil
}

// RegisterTopicForAgent signs and stores a topic record for a registered agent (delegation-aware).
func (h *Host) RegisterTopicForAgent(ctx context.Context, agentAddr a2al.Address, topic string, entry protocol.TopicPayload, ttl uint32) error {
	if h == nil || h.node == nil {
		return errors.New("a2al/host: nil host")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[agentAddr]
	h.agentsMu.RUnlock()
	if !ok {
		return fmt.Errorf("a2al/host: unknown agent %s", agentAddr)
	}
	if ttl == 0 {
		ttl = defaultTopicTTL
	}
	if ttl > maxTopicTTLSeconds {
		ttl = maxTopicTTLSeconds
	}
	entry.Topic = topic
	payload, err := protocol.MarshalTopicPayload(entry)
	if err != nil {
		return err
	}
	now := time.Now()
	seq := uint64(now.UnixNano())
	ts := uint64(now.Unix())
	var rec protocol.SignedRecord
	if len(ag.delegationCBOR) > 0 {
		rec, err = protocol.SignRecordDelegated(ag.priv, ag.delegationCBOR, agentAddr, protocol.RecTypeTopic, payload, seq, ts, ttl)
	} else {
		rec, err = protocol.SignRecord(ag.priv, agentAddr, protocol.RecTypeTopic, payload, seq, ts, ttl)
	}
	if err != nil {
		return err
	}
	key := protocol.TopicNodeID(topic)
	return h.node.PublishTopicRecord(ctx, key, rec)
}

// SearchTopic runs AggregateRecords on the topic key and returns verified entries (spec §5.5).
func (h *Host) SearchTopic(ctx context.Context, topic string) ([]protocol.TopicEntry, error) {
	if h == nil || h.node == nil {
		return nil, errors.New("a2al/host: nil host")
	}
	key := protocol.TopicNodeID(topic)
	q := dht.NewQuery(h.node)
	recs, err := q.AggregateRecords(ctx, key, protocol.RecTypeTopic)
	if err != nil {
		if errors.Is(err, dht.ErrNoMatchingRecords) {
			return nil, nil
		}
		return nil, err
	}
	now := time.Now()
	var out []protocol.TopicEntry
	for _, sr := range recs {
		if err := protocol.VerifySignedRecord(sr, now); err != nil {
			continue
		}
		e, err := protocol.TopicEntryFromSignedRecord(sr)
		if err != nil {
			continue
		}
		if e.Topic != topic || protocol.TopicNodeID(e.Topic) != key {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// SearchTopics returns agents registered on all given topics (intersection by AID) (spec §5.5).
// The returned TopicEntry values are taken from the first topic's results; fields from
// subsequent topics are not merged.
func (h *Host) SearchTopics(ctx context.Context, topics []string) ([]protocol.TopicEntry, error) {
	if h == nil || h.node == nil {
		return nil, errors.New("a2al/host: nil host")
	}
	if len(topics) == 0 {
		return nil, errors.New("a2al/host: topics required")
	}
	per := make([]map[string]protocol.TopicEntry, len(topics))
	for i, t := range topics {
		list, err := h.SearchTopic(ctx, t)
		if err != nil {
			return nil, err
		}
		m := make(map[string]protocol.TopicEntry)
		for _, e := range list {
			m[e.Address.String()] = e
		}
		per[i] = m
	}
	var out []protocol.TopicEntry
	for aid, e := range per[0] {
		ok := true
		for i := 1; i < len(per); i++ {
			if _, o := per[i][aid]; !o {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out, nil
}
