// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

// storeKey identifies a single (AID, Group) replica.
type storeKey struct {
	AID     a2al.Address
	GroupID [32]byte
}

// GroupManager manages the lifecycle of per-AID local Group replicas.
//
// Storage layout: {baseDir}/{aid_hex}/groups/{group_id_hex}/
// where baseDir = dataDir/agents.
//
// Each local AID maintains its own replica; deleting an AID's directory
// automatically removes all its group stores without affecting other members.
//
// All methods are safe for concurrent use.
type GroupManager struct {
	baseDir string // = dataDir/agents
	mu      sync.RWMutex
	open    map[storeKey]*group.Store
	log     *slog.Logger
}

func newGroupManager(dataDir string, log *slog.Logger) *GroupManager {
	gm := &GroupManager{
		baseDir: filepath.Join(dataDir, "agents"),
		open:    make(map[storeKey]*group.Store),
		log:     log,
	}
	// Best-effort migration of legacy shared stores.
	if err := gm.migrateLegacy(dataDir); err != nil {
		log.Warn("group manager: legacy migration failed (old data inaccessible)", "err", err)
	}
	return gm
}

// storeDir returns the canonical filesystem directory for a (AID, Group) replica.
func (gm *GroupManager) storeDir(aid a2al.Address, groupID [32]byte) string {
	return filepath.Join(gm.baseDir, hex.EncodeToString(aid[:]), "groups", hex.EncodeToString(groupID[:]))
}

// Create creates a new Group for aid and returns the opened Store.
func (gm *GroupManager) Create(aid a2al.Address, priv []byte, title string) (*group.Store, error) {
	dir, err := gm.prepareNewGroupDir(aid)
	if err != nil {
		return nil, err
	}

	s, err := group.Create(dir, priv, aid, title)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	id := s.ID()
	finalDir := gm.storeDir(aid, id)
	if err := os.MkdirAll(filepath.Dir(finalDir), 0o700); err != nil {
		_ = s.Close()
		os.RemoveAll(dir)
		return nil, err
	}

	// Close BEFORE renaming: on Windows, os.Rename fails with "Access is denied"
	// if entries.log inside the source directory is still held open.
	_ = s.Close()
	if err := os.Rename(dir, finalDir); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("group manager: rename to final dir: %w", err)
	}

	// Reopen from the canonical path so the Store's internal paths are correct.
	s2, err := group.Open(finalDir)
	if err != nil {
		return nil, err
	}
	gm.mu.Lock()
	gm.open[storeKey{AID: aid, GroupID: id}] = s2
	gm.mu.Unlock()
	return s2, nil
}

// prepareNewGroupDir creates a temporary directory under the AID's groups dir.
func (gm *GroupManager) prepareNewGroupDir(aid a2al.Address) (string, error) {
	aidGroupsDir := filepath.Join(gm.baseDir, hex.EncodeToString(aid[:]), "groups")
	if err := os.MkdirAll(aidGroupsDir, 0o700); err != nil {
		return "", fmt.Errorf("group manager: mkdir: %w", err)
	}
	tmp, err := os.MkdirTemp(aidGroupsDir, ".new-")
	if err != nil {
		return "", fmt.Errorf("group manager: mkdirtemp: %w", err)
	}
	return tmp, nil
}

// Open returns the Store for (aid, groupID), opening from disk if not cached.
func (gm *GroupManager) Open(aid a2al.Address, groupID [32]byte) (*group.Store, error) {
	key := storeKey{AID: aid, GroupID: groupID}

	gm.mu.RLock()
	if s, ok := gm.open[key]; ok {
		gm.mu.RUnlock()
		return s, nil
	}
	gm.mu.RUnlock()

	gm.mu.Lock()
	defer gm.mu.Unlock()
	if s, ok := gm.open[key]; ok {
		return s, nil
	}
	s, err := group.Open(gm.storeDir(aid, groupID))
	if err != nil {
		if errors.Is(err, group.ErrNoStore) {
			return nil, fmt.Errorf("aid %s has no local replica of group %x: call group_join with the invite link (or with group_id plus creator_aid) before reading or appending; group_list shows which groups this aid has joined",
				aid, groupID[:8])
		}
		return nil, fmt.Errorf("group manager: open %x (aid %x): %w", groupID[:4], aid[:4], err)
	}
	gm.open[key] = s
	return s, nil
}

// Join initialises or opens the local Group store for a joining member.
func (gm *GroupManager) Join(aid a2al.Address, groupID [32]byte, creatorAID a2al.Address, title string) (*group.Store, error) {
	key := storeKey{AID: aid, GroupID: groupID}

	// Fast path: already cached.
	gm.mu.RLock()
	if s, ok := gm.open[key]; ok {
		gm.mu.RUnlock()
		return s, nil
	}
	gm.mu.RUnlock()

	finalDir := gm.storeDir(aid, groupID)
	if _, err := os.Stat(finalDir); err == nil {
		// Directory already exists from a prior join; just open it.
		return gm.Open(aid, groupID)
	}

	if err := os.MkdirAll(filepath.Dir(finalDir), 0o700); err != nil {
		return nil, fmt.Errorf("group manager: mkdir: %w", err)
	}

	s, err := group.Join(finalDir, groupID, creatorAID, title)
	if err != nil {
		return nil, err
	}
	gm.mu.Lock()
	gm.open[key] = s
	gm.mu.Unlock()
	return s, nil
}

// List returns the metadata of all locally stored Groups for aid.
func (gm *GroupManager) List(aid a2al.Address) ([]group.Meta, error) {
	aidGroupsDir := filepath.Join(gm.baseDir, hex.EncodeToString(aid[:]), "groups")
	dirs, err := os.ReadDir(aidGroupsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var metas []group.Meta
	for _, d := range dirs {
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		dir := filepath.Join(aidGroupsDir, d.Name())
		m, err := group.ReadMeta(dir)
		if err != nil {
			gm.log.Debug("group manager: skip dir (no valid meta)", "dir", d.Name(), "err", err)
			continue
		}
		metas = append(metas, m)
	}
	return metas, nil
}

// --- legacy migration ---

// migrateLegacy detects the old shared-store layout (dataDir/groups/{group_id}/)
// and converts each store to per-AID replicas for every member AID that is
// registered as a local agent on this daemon.
//
// Migration is best-effort: any individual group that fails to migrate is
// skipped with a warning; the daemon continues to start normally. After a
// successful migration of all groups, the old directory is renamed to
// dataDir/groups.migrated so it is not re-processed on subsequent starts.
func (gm *GroupManager) migrateLegacy(dataDir string) error {
	oldBase := filepath.Join(dataDir, "groups")
	if _, err := os.Stat(oldBase); os.IsNotExist(err) {
		return nil // no legacy data
	}

	// Read local AID directories from dataDir/agents/ to know which AIDs to check.
	aidDirs, err := os.ReadDir(gm.baseDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var localAIDs []a2al.Address
	for _, d := range aidDirs {
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		b, err := hex.DecodeString(d.Name())
		if err != nil || len(b) != 21 {
			continue
		}
		var aid a2al.Address
		copy(aid[:], b)
		localAIDs = append(localAIDs, aid)
	}

	gm.log.Info("group manager: migrating legacy shared stores", "old_dir", oldBase, "local_aids", len(localAIDs))

	groupDirs, err := os.ReadDir(oldBase)
	if err != nil {
		return err
	}

	for _, gd := range groupDirs {
		if !gd.IsDir() || strings.HasPrefix(gd.Name(), ".") {
			continue
		}
		srcDir := filepath.Join(oldBase, gd.Name())
		if err := gm.migrateOneGroup(srcDir, localAIDs); err != nil {
			gm.log.Warn("group manager: migration skipped for group", "dir", gd.Name(), "err", err)
		}
	}

	// Rename old directory so we don't repeat migration on next start.
	migratedName := oldBase + ".migrated"
	if err := os.Rename(oldBase, migratedName); err != nil {
		gm.log.Warn("group manager: could not rename old groups dir", "err", err)
	} else {
		gm.log.Info("group manager: legacy migration complete", "renamed_to", migratedName)
	}
	return nil
}

// migrateOneGroup reads a single old shared group store and creates per-AID
// copies for every local AID that is a member of that group.
func (gm *GroupManager) migrateOneGroup(srcDir string, localAIDs []a2al.Address) error {
	// Read metadata first (fast, no entry scan needed).
	meta, err := group.ReadMeta(srcDir)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}

	// Determine which local AIDs are members by migrating to a temp store and
	// replaying the membership log.  We create the temp store in memory by
	// doing a full read of legacy entries to get the member set.
	//
	// To avoid duplicating the migration logic across AIDs we create one
	// representative store, replay members, then hard-link or copy to each
	// member AID's directory.
	//
	// For simplicity in this migration path, we create ONE copy first (for the
	// creator AID if local, otherwise for the first matching member), replay
	// members, then copy the entries.log to each additional member.

	// Create a temporary migration store for member detection.
	tmpDir, err := os.MkdirTemp("", "a2al-migrate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Write meta so group.Join works.
	tmpStore, err := group.Join(tmpDir, meta.GroupID, meta.CreatorAID, meta.Title)
	if err != nil {
		return fmt.Errorf("create temp store: %w", err)
	}
	n, err := group.MigrateFromLegacy(tmpStore, srcDir)
	if err != nil {
		_ = tmpStore.Close()
		return fmt.Errorf("migrate entries: %w", err)
	}
	ms, err := tmpStore.Members()
	_ = tmpStore.Close()
	if err != nil {
		return fmt.Errorf("replay members: %w", err)
	}

	gm.log.Debug("group manager: migrating group",
		"group", hex.EncodeToString(meta.GroupID[:4]),
		"entries", n,
	)

	// Copy to each matching local AID.
	for _, aid := range localAIDs {
		if ms.Role(aid) < group.RolePending {
			continue // this AID was not a member
		}
		dstDir := gm.storeDir(aid, meta.GroupID)
		if _, err := os.Stat(dstDir); err == nil {
			continue // already exists; skip
		}
		if err := os.MkdirAll(filepath.Dir(dstDir), 0o700); err != nil {
			gm.log.Warn("group manager: mkdir for migrated store", "aid", hex.EncodeToString(aid[:4]), "err", err)
			continue
		}
		// Copy tmpDir → dstDir.
		if err := copyDir(tmpDir, dstDir); err != nil {
			gm.log.Warn("group manager: copy migrated store", "aid", hex.EncodeToString(aid[:4]), "err", err)
			os.RemoveAll(dstDir)
		} else {
			gm.log.Info("group manager: migrated group for AID",
				"aid", hex.EncodeToString(aid[:4]),
				"group", hex.EncodeToString(meta.GroupID[:4]),
			)
		}
	}
	return nil
}

// copyDir recursively copies src to dst (dst must not exist).
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dstPath, data, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}
