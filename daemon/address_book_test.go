// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAddressBook_getEmpty(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/node/address-book")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got addressBookDisk
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Imported || got.Aliases == nil || got.Favorites == nil {
		t.Fatalf("empty book %+v", got)
	}
	if len(got.Aliases) != 0 || len(got.Favorites) != 0 {
		t.Fatalf("want empty, got %+v", got)
	}
}

func TestAddressBook_putGetAndReload(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	body := addressBookDisk{
		Imported: true,
		Aliases:  map[string]string{"aid1": "家"},
		Favorites: []addressBookFav{{
			ID: 1, AID: "aid1", Skill: "chat", Protocols: []string{"mcp"}, AddedAt: 9,
		}},
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/node/address-book", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PUT status %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/node/address-book")
	if err != nil {
		t.Fatal(err)
	}
	var got addressBookDisk
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !got.Imported || got.Aliases["aid1"] != "家" || len(got.Favorites) != 1 || got.Favorites[0].AID != "aid1" {
		t.Fatalf("got %+v", got)
	}

	d2 := newAddressBookRuntime(d.dataDir)
	if err := d2.load(); err != nil {
		t.Fatal(err)
	}
	snap := d2.snapshot()
	if !snap.Imported || snap.Aliases["aid1"] != "家" {
		t.Fatalf("reload %+v", snap)
	}
}

func TestAddressBook_badFileStaysEmpty(t *testing.T) {
	d := newTestDaemon(t)
	if err := os.WriteFile(filepath.Join(d.dataDir, "address_book.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	d2 := newAddressBookRuntime(d.dataDir)
	if err := d2.load(); err == nil {
		t.Fatal("want load error")
	}
}

func TestAddressBook_putInvalidJSON(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/node/address-book", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
