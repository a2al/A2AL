// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestRegisterLocalObject(t *testing.T) {
	d := newTestDaemon(t)
	path := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, n, name, err := d.registerLocalObject(d.nodeAddr, path)
	if err != nil || n != 3 || name != "a.bin" {
		t.Fatalf("id=%x n=%d name=%q err=%v", id, n, name, err)
	}
	got, size, ok := d.lookupLocalObject(d.nodeAddr, id)
	if !ok || got != path || size != 3 {
		t.Fatalf("lookup path=%q size=%d ok=%v", got, size, ok)
	}
}

func TestRegisterLocalObjectFilesRoot(t *testing.T) {
	d := newTestDaemon(t)
	root := t.TempDir()
	d.cfg.FilesRoot = root
	outside := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.registerLocalObject(d.nodeAddr, outside); err == nil {
		t.Fatal("expected files_root rejection")
	}
	inside := filepath.Join(root, "y.bin")
	if err := os.WriteFile(inside, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.registerLocalObject(d.nodeAddr, inside); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterLocalObjectConcurrent(t *testing.T) {
	d := newTestDaemon(t)
	dir := t.TempDir()
	const n = 8
	ids := make([][32]byte, n)
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := filepath.Join(dir, strconv.Itoa(i)+".bin")
			if err := os.WriteFile(p, []byte{byte(i), 1, 2, 3}, 0o600); err != nil {
				errCh <- err
				return
			}
			id, _, _, err := d.registerLocalObject(d.nodeAddr, p)
			if err != nil {
				errCh <- err
				return
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	for i, id := range ids {
		if _, _, ok := d.lookupLocalObject(d.nodeAddr, id); !ok {
			t.Fatalf("missing object %d after concurrent put", i)
		}
	}
}

func TestCopyFileSameFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(p, p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "keep" {
		t.Fatalf("got %q err=%v", b, err)
	}
}

func TestWriteCASFilePreservesDestOnMismatch(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(dest, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("expected"))
	err := writeCASFile(bytes.NewReader([]byte("wrong")), dest, want)
	if err == nil {
		t.Fatal("expected hash mismatch")
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != "original" {
		t.Fatalf("dest %q err=%v", b, err)
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Fatalf("part file leftover: %v", err)
	}
}

func TestWriteCASFileReplacesOnMatch(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := []byte("new-bytes")
	sum := sha256.Sum256(payload)
	if err := writeCASFile(bytes.NewReader(payload), dest, sum); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != "new-bytes" {
		t.Fatalf("dest %q err=%v", b, err)
	}
}
