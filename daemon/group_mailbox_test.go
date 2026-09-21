// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
)

func TestPackInviteNoteFitsMailboxCap(t *testing.T) {
	from, to, pub := mailboxTestPair(t)
	link := "a2al://" + from.String() + "/groups/" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	title := "room title for packing"

	hints := make([]string, 12)
	for i := range hints {
		_, aid := mailboxTestAID(t)
		hints[i] = aid.String()
	}
	body, used := packInviteNote(from, to, pub, link, title, hints)
	if _, err := protocol.EncodeMailboxPayload(from, to, pub, protocol.MailboxMsgGroupInvite, body); err != nil {
		t.Fatalf("packed note does not fit: %v", err)
	}
	var n inviteNote
	if err := json.Unmarshal(body, &n); err != nil {
		t.Fatal(err)
	}
	if n.Link != link {
		t.Fatalf("link dropped")
	}
	if len(used) == 0 {
		t.Fatal("expected at least one hint to fit")
	}
	if len(used) > len(hints) {
		t.Fatalf("used %d hints, only %d candidates", len(used), len(hints))
	}
}

func TestFitJoinNoticeFitsMailboxCap(t *testing.T) {
	from, to, pub := mailboxTestPair(t)
	n := joinNotice{
		Kind:   "group_join",
		Link:   "a2al://" + from.String() + "/groups/" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Status: joinNoticeGaveUp,
		Reason: strings.Repeat("x", joinNoticeReasonCap),
	}
	body := fitJoinNotice(from, to, pub, n)
	if _, err := protocol.EncodeMailboxPayload(from, to, pub, protocol.MailboxMsgText, body); err != nil {
		t.Fatalf("join notice does not fit: %v", err)
	}
	var got joinNotice
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != "group_join" || got.Status != joinNoticeGaveUp {
		t.Fatalf("got %+v", got)
	}
}

func mailboxTestPair(t *testing.T) (a2al.Address, a2al.Address, ed25519.PublicKey) {
	t.Helper()
	_, from := mailboxTestAID(t)
	pub, aid := mailboxTestAID(t)
	return from, aid, pub
}

func mailboxTestAID(t *testing.T) (ed25519.PublicKey, a2al.Address) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, aid
}
