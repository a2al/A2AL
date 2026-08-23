// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

func testUDP(ip string) net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 9}
}

func newTestAddr(t *testing.T) a2al.Address {
	t.Helper()
	ks, err := nodeks.LoadOrGenerate(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	return ks.Address()
}

func TestRemoteAdmin_decideOffIsOpen(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	if !d.decideAccess(d.nodeAddr, remote, "", testUDP("10.0.0.1")) {
		t.Fatal("disabled remote admin must allow (control plane / mailbox)")
	}
}

func TestRemoteAdmin_denyDefault(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	if d.decideAccess(d.nodeAddr, remote, "", testUDP("10.0.0.2")) {
		t.Fatal("enabled + empty allow must deny")
	}
}

func TestRemoteAdmin_allowList(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	if _, err := d.ra.addEntry("allow", aclEntryReq{AID: remote.String()}); err != nil {
		t.Fatal(err)
	}
	if !d.decideAccess(d.nodeAddr, remote, "", testUDP("10.0.0.3")) {
		t.Fatal("allow-listed AID must pass")
	}
}

func TestRemoteAdmin_joinPassword(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ra.addEntry("allow", aclEntryReq{Secret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	if d.decideAccess(d.nodeAddr, remote, "wrong", testUDP("10.0.0.4")) {
		t.Fatal("wrong password must fail")
	}
	if !d.decideAccess(d.nodeAddr, remote, "s3cret", testUDP("10.0.0.4")) {
		t.Fatal("correct password must pass")
	}
	if !d.ra.allows(remote, "") {
		t.Fatal("successful join must persist named allow")
	}
}

func TestRemoteAdmin_fiveFailsBan(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ra.addEntry("allow", aclEntryReq{Secret: "pw"}); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	src := testUDP("10.0.1.5")
	for i := 0; i < raAIDFailBan; i++ {
		if d.decideAccess(d.nodeAddr, remote, "nope", src) {
			t.Fatalf("attempt %d should fail", i)
		}
	}
	snap := d.ra.snapshot()
	var banned bool
	for _, e := range snap.ACL.Deny {
		if e.AID == remote.String() {
			banned = true
		}
	}
	if !banned {
		t.Fatal("AID should be on deny list after 5 wrong passwords")
	}
	if snap.LastBad == nil || snap.LastBad.AID != remote.String() {
		t.Fatal("last_bad_secret not recorded")
	}
}

func TestRemoteAdmin_fifteenFailsRevokeJoin(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	keeper := newTestAddr(t)
	if _, err := d.ra.addEntry("allow", aclEntryReq{AID: keeper.String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ra.addEntry("allow", aclEntryReq{Secret: "pw"}); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	src := testUDP("10.0.1.6")
	for i := 0; i < raJoinFailRevoke; i++ {
		d.decideAccess(d.nodeAddr, remote, "nope", src)
	}
	if !d.ra.enabled() {
		t.Fatal("wrong passwords must not disable remote admin")
	}
	if joinPasswordSet(d.ra.snapshot().ACL) {
		t.Fatal("15 consecutive wrong passwords must clear the join password")
	}
	if !d.ra.allows(keeper, "") {
		t.Fatal("allow-listed AID must still pass after join password is revoked")
	}
}

func TestRemoteAdmin_successClearsJoinFailStreak(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}
	keeper := newTestAddr(t)
	if _, err := d.ra.addEntry("allow", aclEntryReq{AID: keeper.String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ra.addEntry("allow", aclEntryReq{Secret: "pw"}); err != nil {
		t.Fatal(err)
	}
	attacker := newTestAddr(t)
	src := testUDP("10.0.1.7")
	for i := 0; i < raJoinFailRevoke-1; i++ {
		d.decideAccess(d.nodeAddr, attacker, "nope", src)
	}
	if !d.decideAccess(d.nodeAddr, keeper, "", testUDP("10.0.1.8")) {
		t.Fatal("allow-listed access should succeed")
	}
	for i := 0; i < raJoinFailRevoke-1; i++ {
		d.decideAccess(d.nodeAddr, attacker, "nope", src)
	}
	if !joinPasswordSet(d.ra.snapshot().ACL) {
		t.Fatal("successful access must reset the wrong-password streak")
	}
}

func TestRemoteAdmin_apiRoundTrip(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/node/remote-admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != false {
		t.Fatalf("enabled=%v", got["enabled"])
	}

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/node/remote-admin", bytes.NewBufferString(`{"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PATCH status %d", resp.StatusCode)
	}
	if !d.ra.enabled() {
		t.Fatal("PATCH enable did not persist")
	}
}

func TestRemoteAdmin_nodeDenyKeepsQUIC(t *testing.T) {
	a := newTestDaemon(t)
	if err := a.ra.setEnabled(true); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ksB, err := nodeks.LoadOrGenerate(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := host.New(host.Config{
		KeyStore:         ksB,
		ListenAddr:       "127.0.0.1:0",
		QUICListenAddr:   "127.0.0.1:0",
		MinObservedPeers: 1,
		FallbackHost:     "127.0.0.1",
		DisableUPnP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	conn, err := hb.Connect(ctx, a.nodeAddr, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	if !hb.PeerServiceStream(conn) {
		t.Fatal("dialer should see 0x06 ServiceStream")
	}
	_, err = host.AdmitServiceStream(ctx, conn, "")
	if !errors.Is(err, protocol.ErrAccessDenied) {
		t.Fatalf("AdmitServiceStream: %v", err)
	}
	select {
	case <-conn.Context().Done():
		t.Fatal("QUIC should stay up after stream deny")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRemoteAdmin_forceDenyDefaultOnLoad(t *testing.T) {
	d := newTestDaemon(t)
	d.ra.disk.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultPublic}
	d.ra.disk.Enabled = true
	if err := d.ra.persistLocked(); err != nil {
		t.Fatal(err)
	}
	d2 := newRemoteAdminRuntime(d.dataDir)
	if err := d2.load(); err != nil {
		t.Fatal(err)
	}
	if d2.disk.ACL.Default != registry.ACLDefaultDeny {
		t.Fatalf("default=%q", d2.disk.ACL.Default)
	}
}
