// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"crypto/sha256"

	"github.com/a2al/a2al"
)

var topicKeyPrefix = []byte("topic:")

// TopicNodeID returns SHA-256("topic:" || topicUTF8) as the DHT key for Topic
// rendezvous (Phase 4 / v2 §10.3). The formula is immutable on the wire.
func TopicNodeID(topic string) a2al.NodeID {
	return sha256.Sum256(append(topicKeyPrefix, topic...))
}
