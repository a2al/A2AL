// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al/internal/version"
)

func TestReadState_missingFile(t *testing.T) {
	dir := t.TempDir()
	st, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Fatalf("want nil state, got %#v", st)
	}
}

func TestWriteState_roundTrip(t *testing.T) {
	dir := t.TempDir()
	want := &UpdateState{
		Schema:            stateSchema,
		Status:            StatusPending,
		OldVersion:        "1.0.0",
		NewVersion:        "1.1.0",
		OldChecksumSHA256: "abc",
		ReplacedAt:        time.Unix(1700000000, 0).UTC(),
		Attempts:          2,
	}
	if err := WriteState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != want.Schema || got.Status != want.Status || got.Attempts != want.Attempts {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got.NewVersion != want.NewVersion || got.OldVersion != want.OldVersion {
		t.Fatalf("versions %+v", got)
	}
	if got.OldChecksumSHA256 != want.OldChecksumSHA256 {
		t.Fatal(got.OldChecksumSHA256)
	}
}

// setupRollbackHooks sets test hooks and returns a cleanup func.
func setupRollbackHooks(t *testing.T) (exited *bool, restore func()) {
	t.Helper()
	orig := checkRollbackResolveExeFn
	origExit := checkRollbackExitFn
	b := false
	checkRollbackExitFn = func(code int) {
		b = true
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	}
	return &b, func() {
		checkRollbackResolveExeFn = orig
		checkRollbackExitFn = origExit
	}
}

// setVersion temporarily sets version.Version and returns a restore func.
func setVersion(t *testing.T, v string) func() {
	t.Helper()
	orig := version.Version
	version.Version = v
	return func() { version.Version = orig }
}

// ── Guard tests ──────────────────────────────────────────────────────────────

// Guard 3: dev build must skip regardless of state file contents.
func TestCheckAndRollback_devBuildSkips(t *testing.T) {
	defer setVersion(t, "dev")()
	_, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	if err := WriteState(dir, &UpdateState{
		Schema:     stateSchema,
		Status:     StatusPending,
		OldVersion: "1.0.0",
		NewVersion: "dev",
		Attempts:   2,
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	st, _ := ReadState(dir)
	// Attempts must not change — function returned early.
	if st.Attempts != 2 {
		t.Fatalf("attempts=%d want 2 (should have been skipped)", st.Attempts)
	}
}

// Guard 4: NewVersion mismatch — state belongs to a different binary.
func TestCheckAndRollback_versionMismatchSkips(t *testing.T) {
	defer setVersion(t, "1.2.0")()
	_, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	if err := WriteState(dir, &UpdateState{
		Schema:     stateSchema,
		Status:     StatusPending,
		OldVersion: "1.1.0",
		NewVersion: "1.3.0", // different from running version
		Attempts:   2,
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	st, _ := ReadState(dir)
	if st.Attempts != 2 {
		t.Fatalf("attempts=%d want 2 (version mismatch should skip)", st.Attempts)
	}
}

// Guard 5: status != "pending" — already OK or rolled back, must not act.
func TestCheckAndRollback_statusOKSkips(t *testing.T) {
	defer setVersion(t, "9.9.9-test")()
	_, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	if err := WriteState(dir, &UpdateState{
		Schema:     stateSchema,
		Status:     StatusOK,
		OldVersion: "9.9.8",
		NewVersion: "9.9.9-test",
		Attempts:   5,
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	st, _ := ReadState(dir)
	if st.Attempts != 5 {
		t.Fatalf("attempts changed to %d, should stay 5", st.Attempts)
	}
}

// ── Attempt-increment tests ───────────────────────────────────────────────────

func TestCheckAndRollback_attemptIncrementsBelowThree(t *testing.T) {
	defer setVersion(t, "9.9.9-test")()
	_, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	if err := WriteState(dir, &UpdateState{
		Schema:     stateSchema,
		Status:     StatusPending,
		OldVersion: "9.9.8",
		NewVersion: "9.9.9-test",
		Attempts:   1,
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	st, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Attempts != 2 {
		t.Fatalf("attempts=%d want 2", st.Attempts)
	}
	if st.Status != StatusPending {
		t.Fatalf("status=%q", st.Status)
	}
}

// ── Rollback path tests ───────────────────────────────────────────────────────

func TestCheckAndRollback_checksumMismatchRollbackFailed(t *testing.T) {
	defer setVersion(t, "9.9.9-test")()
	exited, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	tmp := t.TempDir()
	fakeExe := filepath.Join(tmp, "fakebin")
	oldExe := oldBinaryPath(fakeExe)

	checkRollbackResolveExeFn = func() (string, error) { return fakeExe, nil }

	if err := os.WriteFile(fakeExe, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldExe, []byte("stored-old"), 0o600); err != nil {
		t.Fatal(err)
	}

	sumWrong := sha256.Sum256([]byte("different-bytes"))
	if err := WriteState(dir, &UpdateState{
		Schema:            stateSchema,
		Status:            StatusPending,
		OldVersion:        "9.9.8",
		NewVersion:        "9.9.9-test",
		Attempts:          2,
		OldChecksumSHA256: hex.EncodeToString(sumWrong[:]),
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	if *exited {
		t.Fatal("exit must not be called on checksum mismatch")
	}
	st, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != StatusRollbackFailed {
		t.Fatalf("status=%q want rollback_failed", st.Status)
	}
	cur, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != "current" {
		t.Fatalf("exe mutated: %q", cur)
	}
}

func TestCheckAndRollback_successRenamesBinary(t *testing.T) {
	defer setVersion(t, "9.9.9-test")()
	exited, restore := setupRollbackHooks(t)
	defer restore()

	dir := t.TempDir()
	tmp := t.TempDir()
	fakeExe := filepath.Join(tmp, "fakebin")
	oldExe := oldBinaryPath(fakeExe)

	checkRollbackResolveExeFn = func() (string, error) { return fakeExe, nil }

	oldBody := []byte("rolled-back-content")
	newBody := []byte("broken-new-binary")
	if err := os.WriteFile(fakeExe, newBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldExe, oldBody, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(oldBody)

	if err := WriteState(dir, &UpdateState{
		Schema:            stateSchema,
		Status:            StatusPending,
		OldVersion:        "9.9.8",
		NewVersion:        "9.9.9-test",
		Attempts:          2,
		OldChecksumSHA256: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatal(err)
	}

	CheckAndRollback(dir)

	if !*exited {
		t.Fatal("expected exit hook to be called")
	}

	st, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != StatusRolledBack {
		t.Fatalf("status=%q", st.Status)
	}

	restored, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(oldBody) {
		t.Fatalf("exe body %q want %q", restored, oldBody)
	}
	failedBody, err := os.ReadFile(fakeExe + ".failed")
	if err != nil {
		t.Fatal(err)
	}
	if string(failedBody) != string(newBody) {
		t.Fatalf(".failed body %q", failedBody)
	}
}

func TestRunSmokeTest_writableDir(t *testing.T) {
	dir := t.TempDir()
	if err := RunSmokeTest(dir); err != nil {
		t.Fatal(err)
	}
}
