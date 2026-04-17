// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	// netWatchPeriod is the passive polling interval for local network fingerprint.
	netWatchPeriod = 10 * time.Second

	// netDebounceBase is the normal confirmation delay before accepting a detected change.
	netDebounceBase = 5 * time.Second
	// netDebounceFlapping is the longer confirmation delay while in flap mode.
	netDebounceFlapping = 45 * time.Second
	// netFlapWindow/netFlapThreshold define the flap detector:
	// >= threshold confirmed changes within window => flap mode.
	netFlapWindow    = 120 * time.Second
	netFlapThreshold = 3

	// nodePublishMinGap prevents overly frequent publish attempts.
	nodePublishMinGap = 30 * time.Second
	// nodePostPublishQuiet suppresses immediate re-triggers right after a publish.
	nodePostPublishQuiet = 30 * time.Second
)

func (d *Daemon) runNetworkMonitor(ctx context.Context) {
	t := time.NewTicker(netWatchPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.pollNetworkFingerprint()
		}
	}
}

func (d *Daemon) pollNetworkFingerprint() {
	now := d.now()
	fp := d.fingerprint()
	if fp == "" {
		return
	}

	d.netMu.Lock()
	d.pruneFlapTimesLocked(now)
	if d.netStableFP == "" {
		d.netStableFP = fp
		d.netPendingFP = ""
		d.netPendingAt = time.Time{}
		d.netMu.Unlock()
		return
	}
	if fp == d.netStableFP {
		d.netPendingFP = ""
		d.netPendingAt = time.Time{}
		d.netMu.Unlock()
		return
	}
	if fp != d.netPendingFP {
		d.netPendingFP = fp
		d.netPendingAt = now
		d.netMu.Unlock()
		return
	}
	debounce := netDebounceBase
	if d.inFlapModeLocked(now) {
		debounce = netDebounceFlapping
	}
	if now.Sub(d.netPendingAt) < debounce {
		d.netMu.Unlock()
		return
	}
	d.netMu.Unlock()

	// Re-sample at debounce expiry to avoid false positives on short reconnects.
	fresh := d.fingerprint()
	if fresh == "" {
		return
	}

	d.netMu.Lock()
	if fresh == d.netStableFP {
		d.netPendingFP = ""
		d.netPendingAt = time.Time{}
		d.netMu.Unlock()
		return
	}
	if fresh != d.netPendingFP {
		d.netPendingFP = fresh
		d.netPendingAt = now
		d.netMu.Unlock()
		return
	}
	d.netStableFP = fresh
	d.netPendingFP = ""
	d.netPendingAt = time.Time{}
	d.netChangeTimes = append(d.netChangeTimes, now)
	d.pruneFlapTimesLocked(now)
	d.netMu.Unlock()
	select {
	case d.netChangeNotify <- struct{}{}:
	default:
	}
}

func (d *Daemon) pruneFlapTimesLocked(now time.Time) {
	if len(d.netChangeTimes) == 0 {
		return
	}
	cutoff := now.Add(-netFlapWindow)
	i := 0
	for ; i < len(d.netChangeTimes); i++ {
		if d.netChangeTimes[i].After(cutoff) {
			break
		}
	}
	if i > 0 {
		copy(d.netChangeTimes, d.netChangeTimes[i:])
		d.netChangeTimes = d.netChangeTimes[:len(d.netChangeTimes)-i]
	}
}

func (d *Daemon) currentNetworkFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })

	var b strings.Builder
	for _, itf := range ifaces {
		// Track active non-loopback interfaces only.
		if itf.Flags&net.FlagLoopback != 0 {
			continue
		}
		if itf.Flags&net.FlagUp == 0 {
			continue
		}
		b.WriteString(itf.Name)
		b.WriteByte('|')
		b.WriteString(itf.HardwareAddr.String())
		b.WriteByte('|')
		addrs, err := itf.Addrs()
		if err == nil {
			ss := make([]string, 0, len(addrs))
			for _, a := range addrs {
				ss = append(ss, a.String())
			}
			sort.Strings(ss)
			for _, s := range ss {
				b.WriteString(s)
				b.WriteByte(',')
			}
		}
		b.WriteByte(';')
	}
	if ip := daemonOutboundIP(); ip != nil {
		b.WriteString("out=")
		b.WriteString(ip.String())
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func daemonOutboundIP() net.IP {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return ua.IP
}

func (d *Daemon) inFlapModeLocked(now time.Time) bool {
	d.pruneFlapTimesLocked(now)
	return len(d.netChangeTimes) >= netFlapThreshold
}

func (d *Daemon) shouldDeferNodePublishLocked(now time.Time) (bool, string) {
	if d.inFlapModeLocked(now) {
		d.deferredEndpointEval = true
		return true, "flapping"
	}
	if now.Before(d.nodePublishQuietTill) {
		d.deferredEndpointEval = true
		return true, "post_publish_quiet"
	}
	if !d.nodeLastPublish.IsZero() && now.Sub(d.nodeLastPublish) < nodePublishMinGap {
		d.deferredEndpointEval = true
		return true, "min_publish_gap"
	}
	return false, ""
}

func (d *Daemon) now() time.Time {
	if d.testNowFn != nil {
		return d.testNowFn()
	}
	return time.Now()
}

func (d *Daemon) fingerprint() string {
	if d.netFingerprintFn != nil {
		return d.netFingerprintFn()
	}
	return d.currentNetworkFingerprint()
}

func (d *Daemon) tryConsumeNetChangeEvent() bool {
	select {
	case <-d.netChangeNotify:
		return true
	default:
		return false
	}
}

func (d *Daemon) handleNetworkChangeCascade(ctx context.Context) {
	start := d.now()
	d.h.InvalidateNetworkCaches()

	obsCtx, obsCancel := context.WithTimeout(ctx, 10*time.Second)
	observed := d.h.ObserveFromRouting(obsCtx, 8)
	obsCancel()

	probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Second)
	d.h.RunNATProbe(probeCtx)
	probeCancel()

	pubCtx, pubCancel := context.WithTimeout(ctx, 100*time.Second)
	d.maybeRepublishNodeOnEndpointChange(pubCtx)
	pubCancel()

	d.log.Info("network change handled",
		"observed_peers", observed,
		"elapsed", d.now().Sub(start).Truncate(time.Millisecond),
	)
}

func (d *Daemon) handleGuardTick(ctx context.Context) {
	now := d.now()
	d.netMu.Lock()
	// Suppress deferred republish while flapping or inside the quiet window:
	// flap mode means another cascade is likely incoming; quiet window means
	// a publish just completed.  Also skip if we are about to start a cascade
	// (the cascade itself calls maybeRepublishNodeOnEndpointChange, so a
	// concurrent direct republish here would race on nodePublishSeq).
	hasEvent := len(d.netChangeNotify) > 0
	needEval := d.deferredEndpointEval &&
		!d.inFlapModeLocked(now) &&
		now.After(d.nodePublishQuietTill) &&
		!hasEvent
	d.netMu.Unlock()
	if needEval {
		if d.testGuardRepublishFn != nil {
			d.testGuardRepublishFn(ctx)
		} else {
			go func() {
				wctx, cancel := context.WithTimeout(ctx, 100*time.Second)
				d.maybeRepublishNodeOnEndpointChange(wctx)
				cancel()
			}()
		}
	}
	if d.tryConsumeNetChangeEvent() {
		d.startCascadeAsync(ctx)
	}
}

func (d *Daemon) startCascadeAsync(ctx context.Context) {
	d.netMu.Lock()
	if d.netCascadeRunning {
		d.netMu.Unlock()
		return
	}
	d.netCascadeRunning = true
	d.netMu.Unlock()
	go func() {
		defer func() {
			d.netMu.Lock()
			d.netCascadeRunning = false
			d.netMu.Unlock()
		}()
		if d.testGuardCascadeFn != nil {
			d.testGuardCascadeFn(ctx)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		d.handleNetworkChangeCascade(cctx)
		cancel()
	}()
}
