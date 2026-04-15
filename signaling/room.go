// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
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

// AppendQuery sets or replaces a single query key on rawURL.
func AppendQuery(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ICERelayURL returns signalBase with path set to /ice.
func ICERelayURL(signalBase string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(signalBase))
	if err != nil {
		return "", err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", fmt.Errorf("signaling: ICE URL scheme must be ws or wss")
	}
	u.Path = "/ice"
	return u.String(), nil
}

// SubscribeURL returns WebSocket URL for callee persistent registration (/signal).
func SubscribeURL(signalBase string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(signalBase))
	if err != nil {
		return "", err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", fmt.Errorf("signaling: subscribe URL scheme must be ws or wss")
	}
	u.Path = "/signal"
	u.RawQuery = ""
	return u.String(), nil
}

// AppendRoomToICEURL is ICERelayURL + AppendRoomQuery.
func AppendRoomToICEURL(signalBase, room string) (string, error) {
	base, err := ICERelayURL(signalBase)
	if err != nil {
		return "", err
	}
	return AppendRoomQuery(base, room)
}

// DeriveSignalBaseFromHostPort builds ws:// or wss:// base (no path) from host:port.
func DeriveSignalBaseFromHostPort(hostport string) (string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", fmt.Errorf("signaling: empty hostport")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	scheme := "ws"
	if port == 443 || port == 8443 {
		scheme = "wss"
	}
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, portStr)}
	return u.String(), nil
}
