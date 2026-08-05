// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package natmap

import "testing"

func TestEntryBlocksUs(t *testing.T) {
	t.Parallel()
	const (
		port   = 4121
		client = "192.168.1.10"
		other  = "192.168.1.11"
	)
	cases := []struct {
		name     string
		hasEntry bool
		gotPort  uint16
		gotCli   string
		enabled  bool
		desc     string
		want     bool
	}{
		{name: "no entry", hasEntry: false, want: false},
		{name: "other client enabled", hasEntry: true, gotPort: port, gotCli: other, enabled: true, desc: Description, want: true},
		{name: "other client disabled", hasEntry: true, gotPort: port, gotCli: other, enabled: false, want: true},
		{name: "ours enabled", hasEntry: true, gotPort: port, gotCli: client, enabled: true, desc: Description, want: false},
		{name: "ours disabled expired", hasEntry: true, gotPort: port, gotCli: client, enabled: false, want: false},
		{name: "ours wrong internal port", hasEntry: true, gotPort: 4122, gotCli: client, enabled: true, desc: Description, want: true},
		{name: "ours wrong desc", hasEntry: true, gotPort: port, gotCli: client, enabled: true, desc: "other", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := entryBlocksUs(tc.hasEntry, tc.gotPort, tc.gotCli, tc.enabled, tc.desc, port, client)
			if got != tc.want {
				t.Fatalf("entryBlocksUs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOurs(t *testing.T) {
	t.Parallel()
	const (
		port   = 4121
		client = "192.168.1.10"
	)
	cases := []struct {
		name    string
		gotPort uint16
		gotCli  string
		enabled bool
		desc    string
		want    bool
	}{
		{name: "match", gotPort: port, gotCli: client, enabled: true, desc: Description, want: true},
		{name: "empty desc strict", gotPort: port, gotCli: client, enabled: true, desc: "", want: false},
		{name: "other desc", gotPort: port, gotCli: client, enabled: true, desc: "other-app", want: false},
		{name: "other client", gotPort: port, gotCli: "192.168.1.11", enabled: true, desc: Description, want: false},
		{name: "other internal port", gotPort: 4122, gotCli: client, enabled: true, desc: Description, want: false},
		{name: "disabled", gotPort: port, gotCli: client, enabled: false, desc: Description, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Ours(port, client, tc.gotPort, tc.gotCli, tc.enabled, tc.desc)
			if got != tc.want {
				t.Fatalf("Ours = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMappingCleanupIdempotent(t *testing.T) {
	t.Parallel()
	calls := 0
	m := &Mapping{cleanup: func() { calls++ }}
	m.Cleanup()
	m.Cleanup()
	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls)
	}
}

func TestQUICURL(t *testing.T) {
	t.Parallel()
	if got := QUICURL("1.2.3.4", 4121); got != "quic://1.2.3.4:4121" {
		t.Fatalf("got %q", got)
	}
}
