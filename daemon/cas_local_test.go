// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a2al/a2al"
)

// Objects must not inherit the API's request-size cap. That cap exists to stop
// a JSON endpoint from making the daemon buffer arbitrary memory; an object is
// streamed straight to disk, so the only ceiling should be the sandbox itself.
// 4 MiB is four times the JSON cap and well past what base64-inside-JSON could
// ever carry, which is the regression this pins down.
func TestCASUploadHasNoSizeCap(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.FilesRoot = t.TempDir()
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	payload := make([]byte, 4<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)

	res := uploadForTest(t, srv.URL, d.nodeAddr, "big.bin", payload, http.StatusOK)
	if res["object_id"] != hex.EncodeToString(want[:]) {
		t.Fatalf("object_id = %v, want %s", res["object_id"], hex.EncodeToString(want[:]))
	}
	if size, _ := res["size"].(float64); int(size) != len(payload) {
		t.Fatalf("size = %v, want %d", res["size"], len(payload))
	}
	if res["name"] != "big.bin" {
		t.Errorf("name = %v, want big.bin", res["name"])
	}

	// The bytes landed in the sandbox under their content hash and are mapped.
	path, size, ok := d.lookupLocalObject(d.nodeAddr, want)
	if !ok {
		t.Fatal("uploaded object was not mapped for the AID")
	}
	if size != int64(len(payload)) {
		t.Errorf("mapped size = %d, want %d", size, len(payload))
	}
	if filepath.Dir(path) != filepath.Clean(d.cfg.FilesRoot) {
		t.Errorf("object stored at %s, expected it inside files_root %s", path, d.cfg.FilesRoot)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Error("stored bytes differ from what was uploaded")
	}

	// No .part leftovers from the streaming write.
	entries, err := os.ReadDir(d.cfg.FilesRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// Content addressing makes a repeated upload a no-op rather than a conflict.
func TestCASUploadIsIdempotent(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.FilesRoot = t.TempDir()
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	payload := []byte("the same bytes twice")
	first := uploadForTest(t, srv.URL, d.nodeAddr, "a.txt", payload, http.StatusOK)
	second := uploadForTest(t, srv.URL, d.nodeAddr, "b.txt", payload, http.StatusOK)

	if first["object_id"] != second["object_id"] {
		t.Fatalf("same bytes produced different ids: %v vs %v", first["object_id"], second["object_id"])
	}
	entries, err := os.ReadDir(d.cfg.FilesRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("files_root holds %d entries, want 1", len(entries))
	}
}

// Upload is a local-only operation. Accepting bytes for an AID this node does
// not hold would make address resolution double as content hosting.
func TestCASUploadRejectsForeignAID(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.FilesRoot = t.TempDir()
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	var foreign a2al.Address
	foreign[0] = 0xA0
	foreign[1] = 0x99
	uploadForTest(t, srv.URL, foreign, "x.bin", []byte("nope"), http.StatusNotFound)
}

// Without a sandbox there is nowhere to put the bytes, and the architecture
// forbids copying objects into dataDir. Say so instead of failing obscurely.
func TestCASUploadWithoutFilesRoot(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.FilesRoot = ""
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	res := uploadForTest(t, srv.URL, d.nodeAddr, "x.bin", []byte("nope"), http.StatusConflict)
	if msg, _ := res["error"].(string); !strings.Contains(msg, "files_root") {
		t.Errorf("error should name files_root, got %q", msg)
	}
}

// Exempting the upload route must not loosen the cap everywhere else: a JSON
// control-plane call larger than 1 MiB is still refused.
func TestControlPlaneStillCapped(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()

	body := `{"tool":"a2al_status","args":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp/call", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("2 MiB JSON control-plane request was accepted (status %d)", resp.StatusCode)
	}
}

func uploadForTest(t *testing.T, base string, aid a2al.Address, name string, payload []byte, wantStatus int) map[string]any {
	t.Helper()
	url := base + "/agents/" + aid.String() + "/cas?name=" + name
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status %d (want %d): %s", resp.StatusCode, wantStatus, raw)
	}
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}
