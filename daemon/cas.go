// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

// casRec is one local hash→path mapping for an AID.
type casRec struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type casIndex struct {
	recs map[string]casRec // hex object id → rec
}

func (d *Daemon) casMapPath(aid a2al.Address) string {
	return filepath.Join(d.dataDir, "agents", hex.EncodeToString(aid[:]), "cas-map.json")
}

func (d *Daemon) loadCasIndex(aid a2al.Address) (*casIndex, error) {
	idx := &casIndex{recs: make(map[string]casRec)}
	b, err := os.ReadFile(d.casMapPath(aid))
	if err != nil {
		if os.IsNotExist(err) {
			return idx, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, &idx.recs); err != nil {
		return nil, err
	}
	if idx.recs == nil {
		idx.recs = make(map[string]casRec)
	}
	return idx, nil
}

func (d *Daemon) saveCasIndex(aid a2al.Address, idx *casIndex) error {
	path := d.casMapPath(aid)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(idx.recs)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func underRoot(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (d *Daemon) absUnderFilesRoot(rawPath string) (string, error) {
	abs, err := filepath.Abs(rawPath)
	if err != nil {
		return "", fmt.Errorf("cas: path: %w", err)
	}
	abs = filepath.Clean(abs)
	root := strings.TrimSpace(d.cfg.FilesRoot)
	if root == "" {
		return abs, nil
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("cas: files_root: %w", err)
	}
	if !underRoot(root, abs) {
		return "", fmt.Errorf("cas: path must be under files_root %s", root)
	}
	return abs, nil
}

// mapObject records object_id → abs for aid. The caller has already hashed the
// bytes; this only touches the index, so a freshly ingested multi-gigabyte file
// is never read a second time just to learn what it already knows.
func (d *Daemon) mapObject(aid a2al.Address, id [32]byte, abs string, size int64) error {
	d.casMapMu.Lock()
	defer d.casMapMu.Unlock()
	idx, err := d.loadCasIndex(aid)
	if err != nil {
		return err
	}
	idx.recs[hex.EncodeToString(id[:])] = casRec{Path: abs, Size: size}
	return d.saveCasIndex(aid, idx)
}

// registerLocalObject maps object_id → absPath for aid after hashing the file.
func (d *Daemon) registerLocalObject(aid a2al.Address, rawPath string) (id [32]byte, size int64, name string, err error) {
	abs, err := d.absUnderFilesRoot(rawPath)
	if err != nil {
		return [32]byte{}, 0, "", err
	}
	root := strings.TrimSpace(d.cfg.FilesRoot)
	f, err := os.Open(abs)
	if err != nil {
		hint := ""
		if root != "" {
			hint = "; place the file under files_root, or hand the bytes to a2ald via POST /agents/{aid}/cas"
		}
		return [32]byte{}, 0, "", fmt.Errorf("cas: cannot open %s%s: %w", abs, hint, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return [32]byte{}, 0, "", err
	}
	if st.IsDir() {
		return [32]byte{}, 0, "", errors.New("cas: path is a directory")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return [32]byte{}, 0, "", err
	}
	copy(id[:], h.Sum(nil))
	if err := d.mapObject(aid, id, abs, n); err != nil {
		return [32]byte{}, 0, "", err
	}
	return id, n, filepath.Base(abs), nil
}

// ingestCASObject streams r into the files_root sandbox, names the result after
// its own content hash, and maps it for aid.
//
// Nothing is buffered and the digest is computed during the write, so the only
// ceiling on object size is free disk space. This is the sandbox's entrance for
// agents that a2ald cannot read from directly (container, VM, or a system
// service that cannot see the user's workspace): they hand the bytes in rather
// than a2ald reaching out, which is the direction files_root exists to enforce.
func (d *Daemon) ingestCASObject(aid a2al.Address, r io.Reader, name string) (id [32]byte, size int64, outName string, err error) {
	root := strings.TrimSpace(d.cfg.FilesRoot)
	if root == "" {
		return [32]byte{}, 0, "", errors.New("cas: handing bytes to a2ald requires files_root to be configured; " +
			"without a sandbox a2ald has nowhere to put them — register a path a2ald can read instead")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return [32]byte{}, 0, "", fmt.Errorf("cas: files_root: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return [32]byte{}, 0, "", fmt.Errorf("cas: mkdir files_root: %w", err)
	}

	tmp, err := os.CreateTemp(absRoot, ".ingest-*.part")
	if err != nil {
		return [32]byte{}, 0, "", fmt.Errorf("cas: create temp in files_root: %w", err)
	}
	tmpName := tmp.Name()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), r)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmpName)
		if copyErr != nil {
			return [32]byte{}, 0, "", fmt.Errorf("cas: receive body: %w", copyErr)
		}
		return [32]byte{}, 0, "", fmt.Errorf("cas: close temp: %w", closeErr)
	}
	copy(id[:], h.Sum(nil))

	dest := filepath.Join(absRoot, hex.EncodeToString(id[:])+".bin")
	if err := placeCASTemp(tmpName, dest, n); err != nil {
		return [32]byte{}, 0, "", err
	}

	if err := d.mapObject(aid, id, dest, n); err != nil {
		return [32]byte{}, 0, "", err
	}
	outName = filepath.Base(strings.TrimSpace(name))
	if outName == "." || outName == string(os.PathSeparator) || strings.TrimSpace(name) == "" {
		outName = filepath.Base(dest)
	}
	return id, n, outName, nil
}

// placeCASTemp moves a fully written temp file to its content-addressed name.
// Losing the race to another ingest of the same bytes is success, not failure:
// the destination is named after the hash, so whoever got there first wrote
// exactly the same file.
func placeCASTemp(tmpName, dest string, size int64) error {
	if st, err := os.Stat(dest); err == nil && st.Size() == size {
		os.Remove(tmpName)
		return nil
	}
	if err := os.Rename(tmpName, dest); err != nil {
		if st, serr := os.Stat(dest); serr == nil && st.Size() == size {
			os.Remove(tmpName)
			return nil
		}
		os.Remove(tmpName)
		return fmt.Errorf("cas: place object: %w", err)
	}
	return nil
}

func (d *Daemon) lookupLocalObject(aid a2al.Address, id [32]byte) (path string, size int64, ok bool) {
	idx, err := d.loadCasIndex(aid)
	if err != nil {
		return "", 0, false
	}
	rec, ok := idx.recs[hex.EncodeToString(id[:])]
	if !ok {
		return "", 0, false
	}
	st, err := os.Stat(rec.Path)
	if err != nil || st.IsDir() {
		return "", 0, false
	}
	return rec.Path, st.Size(), true
}

// locateObject: local mapping first; otherwise a URL for hint (author).
// status: available | expired | pending (URL only, not probed).
func (d *Daemon) locateObject(localAID a2al.Address, id [32]byte, hint a2al.Address) map[string]any {
	if path, size, ok := d.lookupLocalObject(localAID, id); ok {
		return map[string]any{
			"status":    "available",
			"path":      path,
			"size":      size,
			"object_id": hex.EncodeToString(id[:]),
			"url":       group.CASURL(localAID, id),
		}
	}
	holder := hint
	if holder == (a2al.Address{}) {
		holder = localAID
	}
	if holder == localAID {
		return map[string]any{
			"status":    "expired",
			"object_id": hex.EncodeToString(id[:]),
		}
	}
	if d.casLocalHolder(holder) {
		if path, size, ok := d.lookupLocalObject(holder, id); ok {
			return map[string]any{
				"status":    "available",
				"path":      path,
				"size":      size,
				"object_id": hex.EncodeToString(id[:]),
				"url":       group.CASURL(holder, id),
			}
		}
	}
	return map[string]any{
		"status":    "pending",
		"url":       group.CASURL(holder, id),
		"object_id": hex.EncodeToString(id[:]),
	}
}

func (d *Daemon) serveCASFile(w http.ResponseWriter, aid a2al.Address, id [32]byte, method string) {
	idx, err := d.loadCasIndex(aid)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	rec, ok := idx.recs[hex.EncodeToString(id[:])]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(rec.Path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if st.Size() != rec.Size {
		http.Error(w, "gone", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+hex.EncodeToString(id[:])+`"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.WriteHeader(http.StatusOK)
	if method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, f)
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	inSt, err := in.Stat()
	if err != nil {
		return err
	}
	if destSt, err := os.Stat(dest); err == nil && os.SameFile(inSt, destSt) {
		return nil
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// writeBodyToFilesRoot places an in-memory body in the sandbox. It exists for
// the MCP body_base64 argument, which has already paid to hold the whole object
// in memory; anything large should reach ingestCASObject as a stream instead.
func (d *Daemon) writeBodyToFilesRoot(aid a2al.Address, data []byte, name string) ([32]byte, int64, string, error) {
	return d.ingestCASObject(aid, bytes.NewReader(data), name)
}

// writeCASFile streams r into dest after hashing. Existing dest is left
// untouched until the digest matches id (writes dest+".part" then renames).
func writeCASFile(r io.Reader, dest string, id [32]byte) error {
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), r)
	cerr := f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if cerr != nil {
		os.Remove(tmp)
		return cerr
	}
	var got [32]byte
	copy(got[:], h.Sum(nil))
	if got != id {
		os.Remove(tmp)
		return fmt.Errorf("cas: hash mismatch")
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(dest)
		if err2 := os.Rename(tmp, dest); err2 != nil {
			os.Remove(tmp)
			return err2
		}
	}
	return nil
}
