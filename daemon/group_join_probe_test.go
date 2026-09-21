// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/a2al/a2al"
)

func TestJoinProbeGivesUpAndClears(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)

	origI, origT, origG, origD := joinProbeInterval, joinProbeTempAfter, joinProbeGiveUpAfter, joinProbeDialTimeout
	joinProbeInterval = 15 * time.Millisecond
	joinProbeTempAfter = 40 * time.Millisecond
	joinProbeGiveUpAfter = 70 * time.Millisecond
	joinProbeDialTimeout = 10 * time.Millisecond
	t.Cleanup(func() {
		joinProbeInterval, joinProbeTempAfter, joinProbeGiveUpAfter, joinProbeDialTimeout = origI, origT, origG, origD
	})

	_, aidB := testSyncIdentity(t)
	_, aidA := testSyncIdentity(t)
	s, err := d.groups.Join(aidB, [32]byte{1, 2, 3}, aidA, "probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.EntryCount() != 0 {
		t.Fatal("join replica should start empty")
	}

	d.startJoinProbe(aidB, s.ID(), aidA, []a2al.Address{aidA}, errors.New("offline"))
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		d.joinProbeMu.Lock()
		_, live := d.joinProbes[alignGroupKey{aidB, s.ID()}]
		d.joinProbeMu.Unlock()
		if !live {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("join probe still running after give-up")
}
