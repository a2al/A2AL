// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"errors"

	"github.com/a2al/a2al"
)

// Join initialises a local Group store for a Group we are joining as a new
// member. Unlike Create, no genesis entry is written — the entry log will be
// populated by a subsequent sync with an existing member.
//
// groupID, creatorAID and title must come from a trusted source such as a
// verified GroupInviteBody. dir must not already contain a Group store.
func Join(dir string, groupID [32]byte, creatorAID a2al.Address, title string) (*Store, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	if isGroupDir(dir) {
		return nil, errors.New("group: directory already contains a group store")
	}
	m := Meta{
		SchemaVersion: schemaVersion,
		GroupID:       groupID,
		CreatorAID:    creatorAID,
		Title:         title,
		CreatedAt:     nowUnix(),
	}
	if err := writeMeta(dir, m); err != nil {
		return nil, err
	}
	// Open the store (creates an empty entries.log).
	return openStore(dir, m)
}
