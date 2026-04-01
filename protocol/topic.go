// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"fmt"
	"unicode/utf8"

	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

// MaxTopicPayloadCBOR is the spec §5.9 cap on SignedRecord.payload for RecType 0x10.
const MaxTopicPayloadCBOR = 512

// MaxTopicBriefRunes is spec §5.3 one-line description limit.
const MaxTopicBriefRunes = 140

// TopicPayload is the CBOR inside SignedRecord.payload for rec_type=0x10 (spec §5.3).
type TopicPayload struct {
	Version   uint8          `cbor:"1,keyasint"`
	Topic     string         `cbor:"2,keyasint"`
	Name      string         `cbor:"3,keyasint"`
	Protocols []string       `cbor:"4,keyasint"`
	Tags      []string       `cbor:"5,keyasint"`
	Brief     string         `cbor:"6,keyasint"`
	Meta      map[string]any `cbor:"7,keyasint,omitempty"`
}

// TopicEntry is the decoded logical view for discovery (spec §5.7), like EndpointRecord.
type TopicEntry struct {
	Address   a2al.Address
	Seq       uint64
	Timestamp uint64
	TTL       uint32
	Version   uint8
	Topic     string
	Name      string
	Protocols []string
	Tags      []string
	Brief     string
	Meta      map[string]any
}

// MarshalTopicPayload canonical-encodes p and enforces size / brief limits. If p.Version == 0, it is treated as 1 for encoding.
func MarshalTopicPayload(p TopicPayload) ([]byte, error) {
	if utf8.RuneCountInString(p.Brief) > MaxTopicBriefRunes {
		return nil, fmt.Errorf("%w: brief exceeds %d runes", ErrInvalidRecord, MaxTopicBriefRunes)
	}
	enc := p
	if enc.Version == 0 {
		enc.Version = 1
	}
	b, err := recordCanonical.Marshal(enc)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxTopicPayloadCBOR {
		return nil, fmt.Errorf("%w: topic payload exceeds %d bytes", ErrInvalidRecord, MaxTopicPayloadCBOR)
	}
	return b, nil
}

// ParseTopicRecord decodes a topic SignedRecord payload.
func ParseTopicRecord(sr SignedRecord) (TopicPayload, error) {
	if sr.RecType != RecTypeTopic {
		return TopicPayload{}, fmt.Errorf("%w: not a topic record", ErrInvalidRecord)
	}
	var tp TopicPayload
	if err := cbor.Unmarshal(sr.Payload, &tp); err != nil {
		return TopicPayload{}, err
	}
	if tp.Topic == "" {
		return TopicPayload{}, fmt.Errorf("%w: empty topic", ErrInvalidRecord)
	}
	if utf8.RuneCountInString(tp.Brief) > MaxTopicBriefRunes {
		return TopicPayload{}, fmt.Errorf("%w: brief too long", ErrInvalidRecord)
	}
	if len(sr.Payload) > MaxTopicPayloadCBOR {
		return TopicPayload{}, fmt.Errorf("%w: topic payload too large", ErrInvalidRecord)
	}
	return tp, nil
}

// TopicEntryFromSignedRecord builds TopicEntry after caller verifies signature / expiry.
func TopicEntryFromSignedRecord(sr SignedRecord) (TopicEntry, error) {
	tp, err := ParseTopicRecord(sr)
	if err != nil {
		return TopicEntry{}, err
	}
	var addr a2al.Address
	copy(addr[:], sr.Address)
	return TopicEntry{
		Address:   addr,
		Seq:       sr.Seq,
		Timestamp: sr.Timestamp,
		TTL:       sr.TTL,
		Version:   tp.Version,
		Topic:     tp.Topic,
		Name:      tp.Name,
		Protocols: append([]string(nil), tp.Protocols...),
		Tags:      append([]string(nil), tp.Tags...),
		Brief:     tp.Brief,
		Meta:      cloneMeta(tp.Meta),
	}, nil
}

func cloneMeta(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// DiscoverFilter is optional client-side filtering (spec §5.5).
type DiscoverFilter struct {
	Protocols []string `json:"protocols,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// FilterTopicEntries applies protocol/tag filters (AND: all filter tags must appear in entry.Tags; at least one protocol match if filter protocols non-empty).
func FilterTopicEntries(in []TopicEntry, f *DiscoverFilter) []TopicEntry {
	if f == nil || (len(f.Protocols) == 0 && len(f.Tags) == 0) {
		return in
	}
	var out []TopicEntry
next:
	for _, e := range in {
		if len(f.Protocols) > 0 {
			if !intersectsString(e.Protocols, f.Protocols) {
				continue
			}
		}
		if len(f.Tags) > 0 {
			for _, want := range f.Tags {
				if !containsString(e.Tags, want) {
					continue next
				}
			}
		}
		out = append(out, e)
	}
	return out
}

func intersectsString(have, want []string) bool {
	for _, w := range want {
		if containsString(have, w) {
			return true
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}
