// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubDaemon serves the endpoints doctor reads. Empty bootstrap ⇒ public net.
func stubDaemon(t *testing.T, status map[string]any, agents []map[string]any, groups int) *Client {
	t.Helper()
	return stubDaemonCfg(t, status, agents, groups, map[string]any{
		"bootstrap":   []string{},
		"api_addr":    "127.0.0.1:2121",
		"listen_addr": ":4121",
	})
}

func stubDaemonCfg(t *testing.T, status map[string]any, agents []map[string]any, groups int, cfg map[string]any) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": agents})
	})
	mux.HandleFunc("/agents/{aid}/groups", func(w http.ResponseWriter, r *http.Request) {
		list := make([]map[string]any, groups)
		for i := range list {
			list[i] = map[string]any{"group_id": "g"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"groups": list})
	})
	// Mirror the real transport: a bare GET on /mcp/ is rejected, which is what
	// the probe reads as "the route exists".
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newClient(srv.URL, "", false)
}

func stateOf(checks []Check, prefix string) string {
	for _, c := range checks {
		if strings.HasPrefix(c.Name, prefix) {
			return c.State
		}
	}
	return "MISSING"
}

func hintOf(checks []Check, prefix string) string {
	for _, c := range checks {
		if strings.HasPrefix(c.Name, prefix) {
			return c.Hint
		}
	}
	return ""
}

func healthyStatus() map[string]any {
	return map[string]any{
		"version": "test", "uptime_seconds": 300.0,
		"network_ready": true, "dht_peers": 40.0, "persistent_service": true,
		"data_dir": "/tmp/a2al-test",
	}
}

func TestDoctorHealthyMachinePasses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	agents := []map[string]any{{
		"aid": "A0E371d5deB5261D2E3922c738C65644EcDd9Bd0B4",
		"published_to_dht": true, "last_publish_at": "2026-09-19T13:00:00Z",
		"service_tcp": ln.Addr().String(),
	}}
	checks := runDoctor(stubDaemon(t, healthyStatus(), agents, 2))

	for _, prefix := range []string{"daemon", "mcp endpoint", "persistence", "identity", "inbound"} {
		if got := stateOf(checks, prefix); got != statePass {
			t.Errorf("%s: got %s, want PASS", prefix, got)
		}
	}
	if got := stateOf(checks, "build"); got != statePass {
		t.Errorf("build: got %s, want PASS", got)
	}
	var buildName string
	for _, c := range checks {
		if strings.HasPrefix(c.Name, "build") {
			buildName = c.Name
			break
		}
	}
	if !strings.Contains(buildName, "cli ") || !strings.Contains(buildName, "daemon test") {
		t.Errorf("build name %q", buildName)
	}
	for _, prefix := range []string{"network", "publish", "rooms", "topology"} {
		if got := stateOf(checks, prefix); got != stateInfo {
			t.Errorf("%s: got %s, want INFO", prefix, got)
		}
	}
	if !strings.Contains(hintOf(checks, "topology"), "public") {
		t.Errorf("topology hint: %q", hintOf(checks, "topology"))
	}
	assertNoUnreliableNetworkVerdict(t, checks)
}

// Unpublished is outbound-only: tell the operator, do not fail the machine.
func TestDoctorUnpublishedAIDIsInfo(t *testing.T) {
	agents := []map[string]any{{"aid": "A0E371d5deB5261D2E3922c738C65644EcDd9Bd0B4", "published_to_dht": false}}
	checks := runDoctor(stubDaemon(t, healthyStatus(), agents, 0))
	if got := stateOf(checks, "publish"); got != stateInfo {
		t.Errorf("publish: got %s, want INFO", got)
	}
	if got := stateOf(checks, "identity"); got != statePass {
		t.Errorf("identity: got %s, want PASS", got)
	}
	for _, c := range checks {
		if c.State == stateFail {
			t.Errorf("unexpected failure: %+v", c)
		}
	}
}

// No service_tcp is normal for outbound-only use: report it, do not fail it.
// A registered address with nothing listening is a different matter.
func TestDoctorInboundReportedNotPunished(t *testing.T) {
	agents := []map[string]any{{"aid": "AID1", "published_to_dht": true}}
	if got := stateOf(runDoctor(stubDaemon(t, healthyStatus(), agents, 0)), "inbound"); got != stateInfo {
		t.Errorf("missing service_tcp: got %s, want INFO", got)
	}

	agents = []map[string]any{{"aid": "AID1", "published_to_dht": true, "service_tcp": "127.0.0.1:1"}}
	if got := stateOf(runDoctor(stubDaemon(t, healthyStatus(), agents, 0)), "inbound"); got != stateWarn {
		t.Errorf("dead service_tcp: got %s, want WARN", got)
	}
}

func TestDoctorPublicDoesNotVerdictFromPeersOrReady(t *testing.T) {
	st := healthyStatus()
	st["network_ready"], st["dht_peers"] = false, 1.0
	checks := runDoctor(stubDaemon(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": true}}, 0))
	if got := stateOf(checks, "network"); got != stateInfo {
		t.Errorf("network: got %s, want INFO (%+v)", got, checks)
	}
	h := hintOf(checks, "network")
	if !strings.Contains(h, "resolve") && !strings.Contains(h, "fetch") {
		t.Errorf("inconclusive network must tell how to verify: %q", h)
	}
	assertNoUnreliableNetworkVerdict(t, checks)
}

func TestDoctorPublicZeroPeersDoesNotDiagnoseJoinFailure(t *testing.T) {
	st := healthyStatus()
	st["network_ready"], st["dht_peers"] = false, 0.0
	checks := runDoctor(stubDaemon(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": true}}, 0))
	if got := stateOf(checks, "network"); got != stateInfo {
		t.Errorf("network: got %s, want INFO", got)
	}
	h := hintOf(checks, "network")
	if !strings.Contains(h, "resolve") && !strings.Contains(h, "fetch") {
		t.Errorf("must tell how to verify, not guess a cause: %q", h)
	}
	assertNoUnreliableNetworkVerdict(t, checks)
}

func TestDoctorLocalStandaloneDoesNotFail(t *testing.T) {
	st := healthyStatus()
	st["network_ready"], st["dht_peers"] = false, 0.0
	cfg := map[string]any{"bootstrap": []string{"127.0.0.1:4121"}, "api_addr": "127.0.0.1:2122", "listen_addr": ":4122"}
	checks := runDoctor(stubDaemonCfg(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": false}}, 0, cfg))
	if got := stateOf(checks, "network"); got != stateInfo {
		t.Errorf("network: got %s, want INFO", got)
	}
	if got := stateOf(checks, "publish"); got != stateInfo {
		t.Errorf("publish: got %s, want INFO", got)
	}
	if !strings.Contains(strings.ToLower(hintOf(checks, "topology")), "local") {
		t.Errorf("topology: %q", hintOf(checks, "topology"))
	}
	for _, c := range checks {
		if c.State == stateFail {
			t.Errorf("unexpected failure: %+v", c)
		}
	}
}

func TestDoctorPrivateNeighborIsSignalNotPassCriterion(t *testing.T) {
	st := healthyStatus()
	st["network_ready"], st["dht_peers"] = false, 1.0
	cfg := map[string]any{"bootstrap": []string{"10.0.0.2:4121"}, "api_addr": "127.0.0.1:2122"}
	checks := runDoctor(stubDaemonCfg(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": true}}, 0, cfg))
	if got := stateOf(checks, "network"); got != stateInfo {
		t.Errorf("network: got %s, want INFO", got)
	}
	if !strings.Contains(hintOf(checks, "topology"), "private") {
		t.Errorf("topology: %q", hintOf(checks, "topology"))
	}
	if !strings.Contains(hintOf(checks, "network"), "routing table") {
		t.Errorf("network should report the observation, not a threshold: %q", hintOf(checks, "network"))
	}
	assertNoUnreliableNetworkVerdict(t, checks)
}

// A daemon that is not persistent still works right now, but a published AID
// on the public/private net goes unreachable once it stops: warn, do not fail.
func TestDoctorNonPersistentWarnsOnly(t *testing.T) {
	st := healthyStatus()
	st["persistent_service"] = false
	checks := runDoctor(stubDaemon(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": true}}, 0))
	if got := stateOf(checks, "persistence"); got != stateWarn {
		t.Errorf("persistence: got %s, want WARN", got)
	}
	if strings.Contains(hintOf(checks, "persistence"), "few minutes") {
		t.Errorf("must not invent remaining TTL: %q", hintOf(checks, "persistence"))
	}
	for _, c := range checks {
		if c.State == stateFail {
			t.Errorf("unexpected failure: %+v", c)
		}
	}
}

func TestDoctorLocalNonPersistentIsInfo(t *testing.T) {
	st := healthyStatus()
	st["persistent_service"] = false
	st["network_ready"], st["dht_peers"] = false, 1.0
	cfg := map[string]any{"bootstrap": []string{"127.0.0.1:4121"}}
	checks := runDoctor(stubDaemonCfg(t, st, []map[string]any{{"aid": "AID1", "published_to_dht": true}}, 0, cfg))
	if got := stateOf(checks, "persistence"); got != stateInfo {
		t.Errorf("persistence: got %s, want INFO", got)
	}
}

func TestDoctorNoDaemonStopsEarly(t *testing.T) {
	checks := runDoctor(newClient("http://127.0.0.1:1", "", false))
	if len(checks) != 1 || checks[0].State != stateFail || checks[0].Name != "daemon" {
		t.Fatalf("expected a single daemon failure, got %+v", checks)
	}
	if !strings.Contains(checks[0].Hint, "a2ald") {
		t.Errorf("hint does not say how to start it: %q", checks[0].Hint)
	}
	if !strings.Contains(checks[0].Hint, "--api") {
		t.Errorf("hint should mention --api for a second instance: %q", checks[0].Hint)
	}
}

func TestAllLoopback(t *testing.T) {
	if !allLoopback([]string{"127.0.0.1:4121", "[::1]:4121"}) {
		t.Fatal("expected loopback")
	}
	if allLoopback([]string{"127.0.0.1:4121", "10.0.0.2:4121"}) {
		t.Fatal("mixed must not be local")
	}
	if allLoopback(nil) {
		t.Fatal("empty is public, not local")
	}
}

func TestDoctorMissingConfigDoesNotAssumePublic(t *testing.T) {
	st := healthyStatus()
	st["network_ready"], st["dht_peers"], st["persistent_service"] = false, 0.0, false
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": []map[string]any{{"aid": "AID1", "published_to_dht": true}}})
	})
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	checks := runDoctor(newClient(srv.URL, "", false))
	if got := stateOf(checks, "topology"); got != stateInfo {
		t.Errorf("topology: got %s, want INFO", got)
	}
	if !strings.Contains(hintOf(checks, "topology"), "unknown") {
		t.Errorf("topology must not assume public: %q", hintOf(checks, "topology"))
	}
	if got := stateOf(checks, "network"); got != stateInfo {
		t.Errorf("network: got %s, want INFO", got)
	}
	if got := stateOf(checks, "persistence"); got == stateWarn {
		t.Errorf("unknown topology must not warn as if publicly findable")
	}
	assertNoUnreliableNetworkVerdict(t, checks)
}

func TestDoctorRoomsNotGuessedWhenListFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(healthyStatus())
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"bootstrap": []string{}})
	})
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": []map[string]any{{"aid": "AID1"}}})
	})
	mux.HandleFunc("/agents/{aid}/groups", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	checks := runDoctor(newClient(srv.URL, "", false))
	h := hintOf(checks, "rooms")
	if strings.Contains(h, "0 room") {
		t.Errorf("must not invent a room count: %q", h)
	}
	if !strings.Contains(h, "Could not list") {
		t.Errorf("must say the list failed: %q", h)
	}
}

func assertNoUnreliableNetworkVerdict(t *testing.T, checks []Check) {
	t.Helper()
	if got := stateOf(checks, "network"); got == stateFail || got == statePass {
		t.Errorf("network must not PASS/FAIL from local DHT signals: %s", got)
	}
	h := hintOf(checks, "network")
	for _, bad := range []string{
		"Could not join", "Check internet", "ready to be found",
		">= 1", "≥1", "enough to", "60-120", "60–120",
		"normal if this is the first", "Another node on this machine",
	} {
		if strings.Contains(h, bad) {
			t.Errorf("unreliable network claim %q in %q", bad, h)
		}
	}
	for _, c := range checks {
		if c.State == stateFail && c.Name == "network" {
			t.Errorf("network FAIL is a verdict: %+v", c)
		}
	}
}
