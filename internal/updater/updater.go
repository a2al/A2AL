// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package updater

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"

	"github.com/a2al/a2al/internal/version"
)

const (
	checkInterval        = 24 * time.Hour
	initialDelay         = 5 * time.Minute
	rolloutWindow        = 48 * time.Hour
	watchdogTimeout      = 15 * time.Minute // hard deadline before forcing exit
	watchdogSuccessAfter = 8 * time.Minute  // min uptime before marking success; < watchdogTimeout
	httpTimeout          = 60 * time.Second

	githubLatestURL  = "https://api.github.com/repos/a2al/a2al/releases/latest"
	githubTagURL     = "https://api.github.com/repos/a2al/a2al/releases/tags/v%s"
	checksumURLFmt   = "https://github.com/a2al/a2al/releases/download/v%s/a2al_%s_checksums.txt"
	downloadURLFmt   = "https://github.com/a2al/a2al/releases/download/v%s/a2al_%s_%s_%s%s"
)

// Updater manages periodic update checks, binary replacement, and the
// post-update health watchdog. It is created by daemon.New and started
// by daemon.Run via Run(ctx).
type Updater struct {
	dataDir           string
	nodeIDHex         string      // hex NodeID, used for rollout-window hash
	auto              bool        // from config.Update.Auto
	persistentService bool        // true when running under a service manager that auto-restarts
	networkReady      func() bool // injected by daemon; returns true when DHT is healthy

	log *slog.Logger

	updateMu sync.Mutex // serialises concurrent update attempts

	mu          sync.Mutex
	latestVer   string
	lastCheckAt time.Time
}

// New creates an Updater. networkReady is called by the watchdog to confirm
// the new binary has established DHT connectivity.
// persistentService gates the automatic periodic check loop: when false, the
// loop is suppressed to avoid unrecoverable outages on manually-run daemons.
func New(dataDir, nodeIDHex string, auto, persistentService bool, networkReady func() bool, log *slog.Logger) *Updater {
	return &Updater{
		dataDir:           dataDir,
		nodeIDHex:         nodeIDHex,
		auto:              auto,
		persistentService: persistentService,
		networkReady:      networkReady,
		log:               log,
	}
}

// Run starts the update subsystem:
//   - If update_state is "pending" for this binary, starts the health watchdog.
//   - If auto is true, starts the periodic check loop after initialDelay.
//
// Blocks until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	state, _ := ReadState(u.dataDir)
	if isPendingForCurrentBinary(state) {
		go u.watchdog(ctx, state)
	}

	// Automatic periodic updates only run when a service manager provides
	// auto-restart guarantees. In plain-process mode a hung/crashing new binary
	// would leave the node permanently unreachable; manual `a2al update` is the
	// safer alternative and still supported.
	if !u.auto || !u.persistentService || version.Version == "dev" {
		<-ctx.Done()
		return
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(initialDelay):
	}

	for {
		u.runCheck(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(checkInterval):
		}
	}
}

// TriggerNow runs an immediate check and applies any available update,
// ignoring the rollout window. Used by POST /update/apply.
func (u *Updater) TriggerNow(ctx context.Context) error {
	if version.Version == "dev" {
		return errors.New("auto-update is disabled for dev builds")
	}
	return u.checkAndApply(ctx, true /* bypass rollout */)
}

// Status returns fields for a2al_status / GET /update/status.
func (u *Updater) Status() map[string]any {
	u.mu.Lock()
	latest := u.latestVer
	checked := u.lastCheckAt
	u.mu.Unlock()

	state, _ := ReadState(u.dataDir)

	statusStr := "none"
	if state != nil && state.Schema == stateSchema {
		statusStr = state.Status
	}

	available := isNewer(latest, version.Version)
	var checkedStr any
	if !checked.IsZero() {
		checkedStr = checked.UTC().Format(time.RFC3339)
	}

	return map[string]any{
		"update_state":      statusStr,
		"update_available":  available,
		"latest_version":    latest,
		"last_update_check": checkedStr,
		"persistent_service": u.persistentService,
	}
}

// watchdog monitors the new binary's health for up to watchdogTimeout after
// startup. If health is not confirmed in time, os.Exit(2) forces a restart
// so the startup counter advances toward rollback.
// Only started when update_state is "pending" for the current binary.
func (u *Updater) watchdog(ctx context.Context, state *UpdateState) {
	start := time.Now()
	deadline := start.Add(watchdogTimeout)
	u.log.Info("update watchdog: started, must confirm health within 15 minutes",
		"new_version", state.NewVersion, "attempt", state.Attempts)

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown — not a failure, do not exit(2).
			return
		case <-time.After(30 * time.Second):
		}

		if time.Since(start) >= watchdogSuccessAfter && u.networkReady() {
			u.markSuccess()
			return
		}

		if time.Now().After(deadline) {
			u.watchdogRollbackAndRestart(state)
		}
	}
}

// watchdogRollbackAndRestart is called when the watchdog deadline expires.
// It attempts to restore .old directly (self-rollback), then exec the old
// binary so the daemon resumes service without external intervention.
// Falls back to os.Exit(2) if rollback is not possible.
func (u *Updater) watchdogRollbackAndRestart(state *UpdateState) {
	u.log.Error("update watchdog: health timeout — attempting self-rollback",
		"new_version", state.NewVersion, "old_version", state.OldVersion)

	exe, err := resolveExe()
	if err != nil {
		u.log.Error("update watchdog: cannot resolve executable, forcing exit", "err", err)
		os.Exit(2)
	}

	oldPath := oldBinaryPath(exe)
	if _, err := os.Stat(oldPath); err != nil {
		u.log.Error("update watchdog: .old binary not found, cannot self-rollback", "path", oldPath)
		os.Exit(2)
	}

	if state.OldChecksumSHA256 != "" {
		sum, hashErr := sha256File(oldPath)
		if hashErr != nil || sum != state.OldChecksumSHA256 {
			u.log.Error("update watchdog: .old checksum mismatch, refusing self-rollback")
			os.Exit(2)
		}
	}

	failedPath := exe + ".failed"
	if err := os.Rename(exe, failedPath); err != nil {
		u.log.Error("update watchdog: rename current→.failed failed", "err", err)
		os.Exit(2)
	}
	if err := os.Rename(oldPath, exe); err != nil {
		_ = os.Rename(failedPath, exe) // best-effort restore
		u.log.Error("update watchdog: rename .old→current failed, attempted restore", "err", err)
		os.Exit(2)
	}

	state.Status = StatusRolledBack
	state.RolledBackAt = time.Now()
	_ = WriteState(u.dataDir, state)

	u.log.Info("update watchdog: self-rollback complete, restarting with previous version",
		"from", state.NewVersion, "to", state.OldVersion)

	restartProcess(exe) // never returns on success; calls os.Exit(0) on failure
}

func (u *Updater) markSuccess() {
	state, err := ReadState(u.dataDir)
	if err != nil || state == nil || !isPendingForCurrentBinary(state) {
		return
	}
	state.Status = StatusOK
	if err := WriteState(u.dataDir, state); err != nil {
		u.log.Warn("update: failed to write success state", "err", err)
		return
	}
	u.log.Info("update: new binary confirmed healthy", "version", state.NewVersion)
}

// runCheck performs one periodic check cycle: fetch latest version, check for
// retraction of current version, and apply update if rollout window is reached.
func (u *Updater) runCheck(ctx context.Context) {
	info, err := u.fetchLatestRelease(ctx)
	if err != nil {
		u.log.Debug("update: version check skipped (GitHub unreachable)", "err", err)
		return
	}

	u.mu.Lock()
	u.latestVer = info.Version
	u.lastCheckAt = time.Now()
	u.mu.Unlock()

	if isNewer(info.Version, version.Version) {
		// Skip automatic retry of a version we already rolled back from.
		// Manual TriggerNow bypasses this check intentionally.
		if st, _ := ReadState(u.dataDir); st != nil &&
			st.Status == StatusRolledBack && st.NewVersion == info.Version {
			u.log.Debug("update: skipping version previously rolled back", "version", info.Version)
			return
		}

		readyAt := info.PublishedAt.Add(u.rolloutDelay(info.Version))
		if time.Now().Before(readyAt) {
			u.log.Debug("update: rollout window not reached",
				"version", info.Version,
				"ready_at", readyAt.Format(time.RFC3339))
			return
		}
		if err := u.checkAndApply(ctx, false); err != nil {
			u.log.Warn("update: apply failed", "err", err)
		}
		return
	}

	// No newer version — check if current version was retracted.
	u.checkRetraction(ctx)
}

// checkAndApply downloads, verifies, smoke-tests, and replaces the binary.
// bypassRollout skips the rollout-window check (for manual triggers).
func (u *Updater) checkAndApply(ctx context.Context, bypassRollout bool) error {
	if !u.updateMu.TryLock() {
		return errors.New("update already in progress")
	}
	defer u.updateMu.Unlock()

	info, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetch release info: %w", err)
	}

	u.mu.Lock()
	u.latestVer = info.Version
	u.lastCheckAt = time.Now()
	u.mu.Unlock()

	if !isNewer(info.Version, version.Version) {
		return nil // already up to date
	}

	if !bypassRollout {
		readyAt := info.PublishedAt.Add(u.rolloutDelay(info.Version))
		if time.Now().Before(readyAt) {
			return nil // not yet our turn
		}
	}

	exe, err := resolveExe()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	// Stage both binaries in the data dir (always writable).
	stagedDaemon := filepath.Join(u.dataDir, daemonStagedName())
	stagedCLI := filepath.Join(u.dataDir, cliStagedName())
	defer os.Remove(stagedDaemon)
	defer os.Remove(stagedCLI)

	u.log.Info("update: downloading", "version", info.Version)
	if err := u.downloadAndExtract(ctx, info.Version, stagedDaemon, stagedCLI); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// Run smoke test on the staged daemon binary.
	u.log.Info("update: running smoke test")
	smokeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(smokeCtx, stagedDaemon, "__smoke-test", "--data-dir", u.dataDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("smoke test failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Copy staged daemon to the binary directory (.new file).
	newExe := exe + ".new"
	oldChecksum, err := sha256File(exe)
	if err != nil {
		return fmt.Errorf("hash current binary: %w", err)
	}
	if err := copyExecutable(stagedDaemon, newExe); err != nil {
		return fmt.Errorf("copy to binary dir (permission?): %w", err)
	}

	// Write update_state.json before replacing.
	state := &UpdateState{
		Schema:            stateSchema,
		Status:            StatusPending,
		OldVersion:        version.Version,
		NewVersion:        info.Version,
		OldChecksumSHA256: oldChecksum,
		ReplacedAt:        time.Now(),
		Attempts:          0,
	}
	if err := WriteState(u.dataDir, state); err != nil {
		_ = os.Remove(newExe)
		return fmt.Errorf("write state: %w", err)
	}

	// Atomic replace: old → .old, new → current.
	if err := atomicReplace(exe, newExe); err != nil {
		_ = os.Remove(newExe)
		_ = os.Remove(stateFilePath(u.dataDir))
		return fmt.Errorf("atomic replace: %w", err)
	}

	// Best-effort: also replace the a2al CLI binary from the same directory.
	// This keeps CLI and daemon versions in sync after each auto-update.
	// Failures are logged but do not abort — a2al is stateless and a version
	// mismatch is tolerable; the daemon restart is the critical operation.
	u.tryReplaceCLI(stagedCLI, filepath.Dir(exe), info.Version)

	// Clean up staged files explicitly before restartProcess: on Unix,
	// syscall.Exec replaces the process image and defer functions never run.
	os.Remove(stagedDaemon)
	os.Remove(stagedCLI)

	u.log.Info("update: binary replaced, restarting",
		"from", version.Version, "to", info.Version)

	// restartProcess never returns.
	// - Unix: syscall.Exec replaces the process image in-place (same PID,
	//   same args) — works correctly in both service and non-service mode.
	// - Windows service: os.Exit(0), SCM restarts the updated binary.
	// - Windows non-service: spawns the new binary with inherited stdio,
	//   then exits, so the daemon resumes without user intervention.
	restartProcess(exe)
	return nil // unreachable
}

// tryReplaceCLI performs a best-effort atomic replacement of the a2al CLI
// binary. It is called after the daemon binary has been replaced successfully.
// Any error is logged and silently ignored.
func (u *Updater) tryReplaceCLI(stagedCLI, binDir, newVersion string) {
	if _, err := os.Stat(stagedCLI); err != nil {
		return // staged CLI was not extracted (unlikely but safe to skip)
	}
	cliExe := filepath.Join(binDir, cliName())
	if _, err := os.Stat(cliExe); err != nil {
		return // a2al not installed alongside a2ald; skip
	}
	cliNew := cliExe + ".new"
	if err := copyExecutable(stagedCLI, cliNew); err != nil {
		u.log.Warn("update: skipping a2al CLI update (copy failed)", "err", err)
		return
	}
	if err := atomicReplace(cliExe, cliNew); err != nil {
		_ = os.Remove(cliNew)
		u.log.Warn("update: a2al CLI replace failed", "err", err)
		return
	}
	u.log.Info("update: a2al CLI updated", "to", newVersion)
}

// checkRetraction uses the dual-probe approach: if old_version is accessible
// but current version is not, the current release was retracted.
func (u *Updater) checkRetraction(ctx context.Context) {
	state, err := ReadState(u.dataDir)
	if err != nil || state == nil || state.OldVersion == "" || state.Status != StatusOK {
		return
	}

	// Step 1: verify old_version is reachable (proves GitHub API is working).
	oldOK := u.releaseExists(ctx, state.OldVersion)
	if !oldOK {
		return // GitHub unreachable or old version also gone — fail-safe
	}

	// Step 2: check if current version is gone.
	if u.releaseExists(ctx, version.Version) {
		return // current version still published, no retraction
	}

	u.log.Warn("update: current version appears retracted, initiating downgrade",
		"current", version.Version, "old", state.OldVersion)
	u.applyRetraction(ctx, state)
}

func (u *Updater) applyRetraction(ctx context.Context, state *UpdateState) {
	if !u.updateMu.TryLock() {
		return
	}

	exe, err := resolveExe()
	if err != nil {
		u.updateMu.Unlock()
		u.log.Error("update retraction: cannot resolve executable", "err", err)
		return
	}

	oldPath := oldBinaryPath(exe)
	if _, statErr := os.Stat(oldPath); statErr == nil {
		// Prefer direct restore from .old — no download needed.
		sum, hashErr := sha256File(oldPath)
		if hashErr == nil && sum == state.OldChecksumSHA256 {
			u.log.Info("update retraction: restoring .old binary", "version", state.OldVersion)
			newState := &UpdateState{
				Schema:            stateSchema,
				Status:            StatusPending,
				OldVersion:        version.Version,
				NewVersion:        state.OldVersion,
				OldChecksumSHA256: "",
				ReplacedAt:        time.Now(),
			}
			if err := WriteState(u.dataDir, newState); err != nil {
				u.updateMu.Unlock()
				u.log.Error("update retraction: write state", "err", err)
				return
			}
			failedPath := exe + ".failed"
			if err := os.Rename(exe, failedPath); err == nil {
				if err := os.Rename(oldPath, exe); err != nil {
					_ = os.Rename(failedPath, exe)
					u.updateMu.Unlock()
					u.log.Error("update retraction: rename failed", "err", err)
					return
				}
			}
			u.updateMu.Unlock()
			restartProcess(exe) // never returns
		}
	}

	// .old not available or checksum mismatch — release lock and let checkAndApply
	// download the current latest safe version.
	u.updateMu.Unlock()

	if err := u.checkAndApply(ctx, true); err != nil {
		u.log.Error("update retraction: download fallback failed", "err", err)
	}
}

// releaseExists checks whether a GitHub release tag exists. Returns false on
// any network error (fail-safe).
func (u *Updater) releaseExists(ctx context.Context, ver string) bool {
	url := fmt.Sprintf(githubTagURL, ver)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// releaseInfo holds the parsed GitHub release response.
type releaseInfo struct {
	Version     string
	PublishedAt time.Time
}

// fetchLatestRelease queries the GitHub releases/latest endpoint.
// Returns an error if GitHub is unreachable or the response is unexpected.
func (u *Updater) fetchLatestRelease(ctx context.Context) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubLatestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var payload struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	ver := strings.TrimPrefix(payload.TagName, "v")
	pub, err := time.Parse(time.RFC3339, payload.PublishedAt)
	if err != nil {
		pub = time.Now()
	}
	return &releaseInfo{Version: ver, PublishedAt: pub}, nil
}

// downloadAndExtract fetches the release archive for the current platform,
// verifies the archive SHA256 against checksums.txt, then extracts the
// a2ald and a2al binaries into destDaemon and destCLI respectively.
// destCLI may not be written if the archive does not contain a2al (unlikely).
func (u *Updater) downloadAndExtract(ctx context.Context, ver, destDaemon, destCLI string) error {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	arcName := fmt.Sprintf("a2al_%s_%s_%s%s", ver, runtime.GOOS, runtime.GOARCH, ext)
	url := fmt.Sprintf(downloadURLFmt, ver, ver, runtime.GOOS, runtime.GOARCH, ext)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: status %d", resp.StatusCode)
	}

	// Write archive to a temp file so we can hash it and extract from it.
	arcTmp := destDaemon + ".arc"
	defer os.Remove(arcTmp)
	arcFile, err := os.OpenFile(arcTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(arcFile, resp.Body); err != nil {
		arcFile.Close()
		return err
	}
	arcFile.Close()

	// Verify archive SHA256 against the official checksums.txt.
	// The checksums.txt hashes are for the archives, not the extracted binaries.
	arcChecksum, err := sha256File(arcTmp)
	if err != nil {
		return err
	}
	if err := u.verifyArchiveChecksum(ctx, ver, arcName, arcChecksum); err != nil {
		return err
	}

	// Extract both binaries from the (now verified) archive.
	daemonBin := "a2ald"
	cliBin := "a2al"
	if runtime.GOOS == "windows" {
		daemonBin = "a2ald.exe"
		cliBin = "a2al.exe"
	}

	extractFn := extractTarGz
	if runtime.GOOS == "windows" {
		extractFn = extractZip
	}

	if err := extractFn(arcTmp, daemonBin, destDaemon); err != nil {
		return fmt.Errorf("extract %s: %w", daemonBin, err)
	}
	// a2al CLI extraction is best-effort — don't fail the update if missing.
	if err := extractFn(arcTmp, cliBin, destCLI); err != nil {
		u.log.Warn("update: could not extract a2al CLI from archive", "err", err)
		_ = os.Remove(destCLI) // ensure no partial file
	}

	return nil
}

// verifyArchiveChecksum downloads checksums.txt and verifies arcChecksum matches
// the expected SHA256 for arcName (e.g. "a2al_0.9.2_linux_amd64.tar.gz").
func (u *Updater) verifyArchiveChecksum(ctx context.Context, ver, arcName, arcChecksum string) error {
	url := fmt.Sprintf(checksumURLFmt, ver, ver)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums.txt: status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if fields[1] == arcName {
			if fields[0] != arcChecksum {
				return fmt.Errorf("checksum mismatch for %s: expected %s got %s",
					arcName, fields[0], arcChecksum)
			}
			return nil
		}
	}
	return fmt.Errorf("checksum entry for %s not found in checksums.txt", arcName)
}

// rolloutDelay returns a stable per-node delay in [0, rolloutWindow) derived
// from the node's identity and the target version, so different nodes upgrade
// at different times within the rollout window.
func (u *Updater) rolloutDelay(ver string) time.Duration {
	h := sha256.Sum256([]byte(u.nodeIDHex + ver))
	n := binary.BigEndian.Uint64(h[:8])
	return time.Duration(n % uint64(rolloutWindow))
}

// isPendingForCurrentBinary returns true when all guards in the rollback chain
// are satisfied, meaning the watchdog should be started.
func isPendingForCurrentBinary(state *UpdateState) bool {
	return state != nil &&
		state.Schema == stateSchema &&
		version.Version != "dev" &&
		state.NewVersion == version.Version &&
		state.Status == StatusPending
}

// isNewer returns true if candidate is a valid semver strictly greater than current.
func isNewer(candidate, current string) bool {
	if candidate == "" || current == "" || current == "dev" {
		return false
	}
	c := "v" + candidate
	cur := "v" + current
	return semver.IsValid(c) && semver.IsValid(cur) && semver.Compare(c, cur) > 0
}

// copyExecutable copies src to dst with executable permissions.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

func daemonStagedName() string {
	if runtime.GOOS == "windows" {
		return "a2ald.staged.exe"
	}
	return "a2ald.staged"
}

func cliStagedName() string {
	if runtime.GOOS == "windows" {
		return "a2al.staged.exe"
	}
	return "a2al.staged"
}

func cliName() string {
	if runtime.GOOS == "windows" {
		return "a2al.exe"
	}
	return "a2al"
}

func httpClient() *http.Client {
	return &http.Client{Timeout: httpTimeout}
}

func extractTarGz(archivePath, binName, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == binName {
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			return err
		}
	}
	return fmt.Errorf("%s not found in archive", binName)
}

func extractZip(archivePath, binName, dst string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				rc.Close()
				return err
			}
			_, err = io.Copy(out, rc)
			out.Close()
			rc.Close()
			return err
		}
	}
	return fmt.Errorf("%s not found in zip", binName)
}
