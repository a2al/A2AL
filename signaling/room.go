// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
)

// RoomID is a deterministic 32-hex room name from two agent address strings (sorted).
func RoomID(aidA, aidB string) string {
	if aidA > aidB {
		aidA, aidB = aidB, aidA
	}
	sum := sha256.Sum256([]byte(aidA + "\n" + aidB))
	return hex.EncodeToString(sum[:16])
}

// AppendRoomQuery adds or replaces the "room" query parameter on signalBase (absolute ws/wss URL).
func AppendRoomQuery(signalBase, room string) (string, error) {
	u, err := url.Parse(signalBase)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("room", room)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
