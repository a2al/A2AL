// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package chat

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/internal/pow"
	"github.com/a2al/a2al/protocol"
)

const (
	KindInvite = "chat.invite"
	KindAccept = "chat.accept"
	KindRefuse = "chat.refuse"
	KindDing   = "chat.ding"
	KindPull   = "chat.pull"
	KindMsg    = "chat.msg"

	MsgText = "t"
	MsgFile = "f"
)

var ErrTooLarge = errors.New("chat: message too large")

type Invite struct {
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	Bits  int    `json:"bits"`
	Note  string `json:"note,omitempty"`
}

type Pull struct {
	After uint64 `json:"after"`
}

type Msg struct {
	Seq    uint64 `json:"seq"`
	TS     int64  `json:"ts"`
	K      string `json:"k"`
	Body   string `json:"body,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Name   string `json:"name,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Author string `json:"author,omitempty"`
	Sig    string `json:"sig,omitempty"`
}

func EncodeInvite(inv Invite) ([]byte, error) {
	inv.Note = TruncateRunes(inv.Note, NoteMaxRunes)
	return json.Marshal(inv)
}

func DecodeInvite(body []byte) (Invite, error) {
	var inv Invite
	if err := json.Unmarshal(body, &inv); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func EncodeEmpty() []byte { return []byte("{}") }

func EncodePull(after uint64) ([]byte, error) {
	return json.Marshal(Pull{After: after})
}

func DecodePull(body []byte) (Pull, error) {
	var p Pull
	if len(body) == 0 {
		return Pull{}, nil
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Pull{}, err
	}
	return p, nil
}

func EncodeMsg(m Msg) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if _, err := protocol.EncodeEnvelopeInner(KindMsg, b); err != nil {
		return nil, ErrTooLarge
	}
	return b, nil
}

func DecodeMsg(body []byte) (Msg, error) {
	var m Msg
	if err := json.Unmarshal(body, &m); err != nil {
		return Msg{}, err
	}
	return m, nil
}

func RecFromMsg(m Msg, peer a2al.Address) (Rec, error) {
	rec := Rec{Seq: m.Seq, TS: m.TS, Body: m.Body, Name: m.Name, Size: m.Size}
	switch m.K {
	case MsgFile:
		rec.Kind = KindFile
	default:
		rec.Kind = KindText
	}
	if m.Ref != "" {
		b, err := hex.DecodeString(m.Ref)
		if err != nil || len(b) != 32 {
			return Rec{}, errors.New("chat: bad ref")
		}
		copy(rec.Ref[:], b)
	}
	if a := strings.TrimSpace(m.Author); a != "" {
		aid, err := a2al.ParseAddress(a)
		if err != nil {
			return Rec{}, errors.New("chat: bad author")
		}
		if aid != peer {
			return Rec{}, errors.New("chat: author mismatch")
		}
		rec.Author = aid
	}
	return rec, nil
}

func MsgFromRec(r Rec) Msg {
	m := Msg{Seq: r.Seq, TS: r.TS, Body: r.Body, Name: r.Name, Size: r.Size}
	if r.Kind == KindFile {
		m.K = MsgFile
	} else {
		m.K = MsgText
	}
	if r.Ref != ([32]byte{}) {
		m.Ref = hex.EncodeToString(r.Ref[:])
	}
	return m
}

func NonceB64(nonce []byte) string {
	return base64.StdEncoding.EncodeToString(nonce)
}

func DecodeNonce(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func VerifyInvite(from, to a2al.Address, inv Invite, nowTS int64) bool {
	if inv.TS <= 0 {
		return false
	}
	age := nowTS - inv.TS
	if age < 0 {
		age = -age
	}
	if age > int64(PowMaxAge.Seconds()) {
		return false
	}
	nonce, err := DecodeNonce(inv.Nonce)
	if err != nil {
		return false
	}
	return pow.Verify(PurposeInvite, from, to, inv.TS, nonce, pow.DefaultBits)
}
