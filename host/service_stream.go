// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// WriteServiceAdmission writes the a2s1 magic, optional AccessToken, and KeysDone.
func WriteServiceAdmission(w io.Writer, token string) error {
	if _, err := io.WriteString(w, protocol.MagicServiceStream); err != nil {
		return err
	}
	if token != "" {
		if len(token) > maxAccessToken {
			return errors.New("a2al/host: access token too long")
		}
		if err := writeCtrlMsg(w, ctrlMsgAccessToken, []byte(token)); err != nil {
			return err
		}
	}
	return writeCtrlMsg(w, ctrlMsgKeysDone, nil)
}

// ReadServiceAdmission drains a2s1 key messages until KeysDone.
// The 4-byte magic must already have been consumed.
func ReadServiceAdmission(r io.Reader) (token string, err error) {
	for {
		msgType, payload, rerr := readCtrlMsg(r)
		if rerr != nil {
			return token, rerr
		}
		switch msgType {
		case ctrlMsgAccessToken:
			if len(payload) > 0 && len(payload) <= maxAccessToken {
				token = string(payload)
			}
		case ctrlMsgKeysDone:
			return token, nil
		}
	}
}

// WriteAccessResult writes allowed (1) or denied (0) plus optional reason.
func WriteAccessResult(w io.Writer, allowed bool, reason string) error {
	res := []byte{1}
	if !allowed {
		if reason == "" {
			reason = "denied"
		}
		res = append([]byte{0}, []byte(reason)...)
	}
	return writeCtrlMsg(w, ctrlMsgAccessResult, res)
}

// ReadAccessResult skips unknown types until AccessResult.
func ReadAccessResult(r io.Reader) (allowed bool, reason string, err error) {
	for {
		msgType, payload, rerr := readCtrlMsg(r)
		if rerr != nil {
			return false, "", rerr
		}
		if msgType != ctrlMsgAccessResult {
			continue
		}
		if len(payload) == 0 || payload[0] != 0 {
			return true, "", nil
		}
		if len(payload) > 1 {
			reason = string(payload[1:])
		}
		return false, reason, nil
	}
}

// AdmitServiceStream opens a stream, runs a2s1 admission, and returns it
// positioned at the business bytes. The caller must only use this when
// PeerServiceStream(conn) is true.
func AdmitServiceStream(ctx context.Context, conn quic.Connection, token string) (quic.Stream, error) {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(dl)
	}
	if err := WriteServiceAdmission(str, token); err != nil {
		_ = str.Close()
		return nil, err
	}
	allowed, _, err := ReadAccessResult(str)
	_ = str.SetDeadline(time.Time{})
	if err != nil {
		_ = str.Close()
		return nil, admitErr(err)
	}
	if !allowed {
		_ = str.Close()
		return nil, protocol.ErrAccessDenied
	}
	return str, nil
}

func admitErr(err error) error {
	var se *quic.StreamError
	if errors.As(err, &se) && uint64(se.ErrorCode) == protocol.StreamErrAccessDenied {
		return protocol.ErrAccessDenied
	}
	return err
}
