// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

// DHT record categories (Phase 4 spec §2.1).
const (
	CategoryUnknown   uint8 = 0
	CategorySovereign uint8 = 1 // RecType 0x01–0x0F
	CategoryTopic     uint8 = 2 // RecType 0x10–0x1F
	CategoryMailbox   uint8 = 3 // RecType 0x80–0x8F
)

// RecType constants beyond endpoint (Phase 4).
const (
	RecTypeTopic   uint8 = 0x10
	RecTypeMailbox uint8 = 0x80
)

// RecordCategory maps RecType to a storage/query policy bucket.
// Reserved ranges (0x20–0x7F, 0x90–0xFF) return CategoryUnknown and are
// stored like sovereign (key must be NodeID(Address)) for forward compatibility.
func RecordCategory(recType uint8) uint8 {
	switch {
	case recType >= 0x01 && recType <= 0x0f:
		return CategorySovereign
	case recType >= 0x10 && recType <= 0x1f:
		return CategoryTopic
	case recType >= 0x80 && recType <= 0x8f:
		return CategoryMailbox
	default:
		return CategoryUnknown
	}
}
