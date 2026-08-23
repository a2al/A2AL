// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

type addressBookFav struct {
	ID        int      `json:"id"`
	AID       string   `json:"aid"`
	Skill     string   `json:"skill,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	AddedAt   int64    `json:"addedAt,omitempty"`
}

type addressBookDisk struct {
	Imported  bool              `json:"imported"`
	Aliases   map[string]string `json:"aliases"`
	Favorites []addressBookFav  `json:"favorites"`
}

type addressBookRuntime struct {
	mu   sync.Mutex
	path string
	disk addressBookDisk
}

func (d *Daemon) initAddressBook() {
	d.book = newAddressBookRuntime(d.dataDir)
	if err := d.book.load(); err != nil && d.log != nil {
		d.log.Warn("address_book load", "err", err)
	}
}

func newAddressBookRuntime(dataDir string) *addressBookRuntime {
	return &addressBookRuntime{
		path: filepath.Join(dataDir, "address_book.json"),
		disk: emptyAddressBook(),
	}
}

func emptyAddressBook() addressBookDisk {
	return addressBookDisk{
		Aliases:   map[string]string{},
		Favorites: []addressBookFav{},
	}
}

func normalizeBook(b addressBookDisk) addressBookDisk {
	if b.Aliases == nil {
		b.Aliases = map[string]string{}
	}
	if b.Favorites == nil {
		b.Favorites = []addressBookFav{}
	}
	out := make([]addressBookFav, 0, len(b.Favorites))
	for _, f := range b.Favorites {
		if f.AID == "" {
			continue
		}
		if f.Protocols == nil {
			f.Protocols = []string{}
		}
		out = append(out, f)
	}
	b.Favorites = out
	return b
}

func (s *addressBookRuntime) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var disk addressBookDisk
	if err := json.Unmarshal(b, &disk); err != nil {
		return err
	}
	s.mu.Lock()
	s.disk = normalizeBook(disk)
	s.mu.Unlock()
	return nil
}

func (s *addressBookRuntime) persistLocked() error {
	s.disk = normalizeBook(s.disk)
	raw, err := json.MarshalIndent(s.disk, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *addressBookRuntime) snapshot() addressBookDisk {
	s.mu.Lock()
	defer s.mu.Unlock()
	aliases := make(map[string]string, len(s.disk.Aliases))
	for k, v := range s.disk.Aliases {
		aliases[k] = v
	}
	favs := append([]addressBookFav{}, s.disk.Favorites...)
	return addressBookDisk{Imported: s.disk.Imported, Aliases: aliases, Favorites: favs}
}

func (s *addressBookRuntime) replace(next addressBookDisk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disk = normalizeBook(next)
	return s.persistLocked()
}

func (d *Daemon) handleAddressBookGet(w http.ResponseWriter, r *http.Request) {
	if d.book == nil {
		writeJSON(w, emptyAddressBook())
		return
	}
	writeJSON(w, d.book.snapshot())
}

func (d *Daemon) handleAddressBookPut(w http.ResponseWriter, r *http.Request) {
	if d.book == nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	var next addressBookDisk
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := d.book.replace(next); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "persist failed"})
		return
	}
	writeJSON(w, d.book.snapshot())
}
