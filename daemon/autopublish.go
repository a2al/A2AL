// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	mrand "math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

const (
	endpointRecordTTL     = uint32(3600)
	republishPeriod       = time.Duration(endpointRecordTTL/2) * time.Second // 30m
	endpointWatchPeriod   = 60 * time.Second
	heartbeatTTL          = time.Duration(endpointRecordTTL) * time.Second
	guardTickPeriod       = 5 * time.Second
	anchorKeepalivePeriod = 20 * time.Second // keep NAT bindings alive; feeds observed-addr back to natsense

	// signalReadyTimeout is how long forcePublishNodeOnce waits for at least
	// one Signal hub to connect before publishing without Signal URLs.
	// Normal hub registration completes well within this window; the timeout
	// is a safety valve for slow or unreachable hubs.
	signalReadyTimeout = 15 * time.Second

	// healthRelaxCap is the maximum remaining backoff applied to all peers
	// during RelaxHealthThrottle. Peers with longer pending backoffs are
	// brought forward to now+cap so probes resume quickly after recovery.
	// 30 s matches two probe-tick intervals (2×15 s), giving the replication
	// loop a short but fair retry window without flooding the network.
	healthRelaxCap = 30 * time.Second
)

type nodePublishDisk struct {
	Seq uint64 `json:"seq"`
}

func (d *Daemon) nodePublishPath() string {
	return filepath.Join(d.dataDir, "node_publish.json")
}

func (d *Daemon) loadNodePublishState() (uint64, error) {
	b, err := os.ReadFile(d.nodePublishPath())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var st nodePublishDisk
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, err
	}
	return st.Seq, nil
}

func (d *Daemon) saveNodePublishState() error {
	d.nodePublishMu.Lock()
	seq := d.nodePublishSeq
	d.nodePublishMu.Unlock()
	b, err := json.MarshalIndent(nodePublishDisk{Seq: seq}, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.nodePublishPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.nodePublishPath())
}

func endpointPayloadFingerprint(ep protocol.EndpointPayload) string {
	var b strings.Builder
	endpoints := slices.Sorted(slices.Values(ep.Endpoints))
	for _, x := range endpoints {
		b.WriteString(x)
		b.WriteByte('|')
	}
	b.WriteString(ep.Signal)
	b.WriteByte('|')
	signals := slices.Sorted(slices.Values(ep.Signals))
	for _, u := range signals {
		b.WriteString(u)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, t := range ep.Turns {
		b.WriteString(t)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(ep.NatType)))
	return b.String()
}

func (d *Daemon) agentAliveForRepublish(e *registry.Entry) bool {
	d.heartbeatMu.Lock()
	t, hbOK := d.heartbeatAt[e.AID]
	d.heartbeatMu.Unlock()
	if hbOK {
		if t.IsZero() {
			// Zero sentinel: forcibly marked inactive (e.g. stale record detected).
			return false
		}
		if time.Since(t) < heartbeatTTL {
			return true
		}
	}
	// No service_tcp means the agent manages its own public reachability (e.g. public URL).
	// In that case heartbeat is the only liveness signal — TCP probe is not applicable.
	if e.ServiceTCP == "" {
		return false
	}
	return probeTCP(e.ServiceTCP, 2*time.Second)
}

func (d *Daemon) recordAgentPublishTime(aid a2al.Address) {
	d.publishMetaMu.Lock()
	if d.agentLastPublish == nil {
		d.agentLastPublish = make(map[a2al.Address]time.Time)
	}
	d.agentLastPublish[aid] = time.Now()
	d.publishMetaMu.Unlock()
}

func (d *Daemon) recordNodePublishTime() {
	now := d.now()
	d.publishMetaMu.Lock()
	d.nodeLastPublish = now
	d.publishMetaMu.Unlock()
	d.netMu.Lock()
	d.nodePublishQuietTill = now.Add(nodePostPublishQuiet)
	d.netMu.Unlock()
}

func (d *Daemon) publishNodeOnce(ctx context.Context) error {
	d.nodePublishMu.Lock()
	nextSeq := d.nodePublishSeq + 1
	d.nodePublishMu.Unlock()

	// Build payload once: used for both publishing and fingerprint caching.
	ep, err := d.h.BuildEndpointPayload(ctx)
	if err != nil {
		return err
	}
	d.publishMetaMu.Lock()
	d.lastEndpointsFP = endpointPayloadFingerprint(ep)
	d.publishMetaMu.Unlock()

	if err := d.h.PublishEndpointBuilt(ctx, ep, nextSeq, endpointRecordTTL); err != nil {
		return err
	}

	d.nodePublishMu.Lock()
	d.nodePublishSeq = nextSeq
	d.nodePublishMu.Unlock()

	if err := d.saveNodePublishState(); err != nil {
		d.log.Warn("node publish state save", "err", err)
	}

	d.recordNodePublishTime()
	d.log.Info("node endpoint published to DHT", "seq", nextSeq)
	return nil
}

func (d *Daemon) maybeRepublishNodeOnEndpointChange(ctx context.Context) {
	if !d.cfg.AutoPublish {
		d.netMu.Lock()
		d.deferredEndpointEval = false
		d.netMu.Unlock()
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	ep, err := d.h.BuildEndpointPayload(pctx)
	cancel()
	if err != nil {
		d.netMu.Lock()
		d.deferredEndpointEval = false
		d.netMu.Unlock()
		return
	}
	fp := endpointPayloadFingerprint(ep)

	d.publishMetaMu.Lock()
	prev := d.lastEndpointsFP
	d.publishMetaMu.Unlock()

	if prev == "" || fp == prev {
		d.netMu.Lock()
		d.deferredEndpointEval = false
		d.netMu.Unlock()
		return
	}

	d.netMu.Lock()
	if deferNow, reason := d.shouldDeferNodePublishLocked(d.now()); deferNow {
		d.netMu.Unlock()
		d.log.Debug("node republish deferred", "reason", reason)
		return
	}
	d.netMu.Unlock()

	// Endpoint (IP/port) changed: republish node record immediately.
	pubCtx, pubCancel := context.WithTimeout(ctx, 90*time.Second)
	if err := d.publishNodeOnce(pubCtx); err != nil {
		d.log.Debug("node republish on endpoint change", "err", err)
		d.netMu.Lock()
		d.deferredEndpointEval = true
		d.netMu.Unlock()
		pubCancel()
		return
	}
	pubCancel()
	d.netMu.Lock()
	d.deferredEndpointEval = false
	d.netMu.Unlock()

	// Also push updated endpoint to all registered agents so their records
	// reflect the new address without waiting for the next periodic tick.
	d.regMu.RLock()
	agents := d.reg.List()
	d.regMu.RUnlock()
	for _, e := range agents {
		d.tryRepublishAgent(ctx, e.AID)
	}
}

// forcePublishNodeOnce publishes the node identity unconditionally, bypassing
// the endpoint-fingerprint gate used by maybeRepublishNodeOnEndpointChange.
// Used after confirmed network changes where the published record must be
// refreshed regardless of whether the local endpoint appears to have changed.
//
// Before publishing it relaxes per-peer health throttles so recovery probes
// can reach previously-throttled peers within healthRelaxCap.  For NAT nodes
// it also waits up to signalReadyTimeout for a Signal hub to connect, so the
// published record includes live Signal URLs.  If no hub connects in time the
// publish proceeds and pendingSignalRepublish is set; flush() will republish
// once a hub comes online.
func (d *Daemon) forcePublishNodeOnce(ctx context.Context) {
	if !d.cfg.AutoPublish {
		d.netMu.Lock()
		d.deferredEndpointEval = false
		d.netMu.Unlock()
		return
	}

	// Prevent concurrent force-publish calls from racing on nodePublishSeq.
	// If a force publish is already in flight, the record will be fresh by the
	// time it finishes; no need for a second one to immediately follow.
	if !d.forcePublishMu.TryLock() {
		return
	}
	defer d.forcePublishMu.Unlock()

	// During rapid network flapping, suppress the publish: a cascade will
	// fire once the topology stabilises, at which point we publish with the
	// correct stable address.
	d.netMu.Lock()
	if d.inFlapModeLocked(d.now()) {
		d.deferredEndpointEval = true
		d.netMu.Unlock()
		d.log.Debug("force node publish suppressed: flapping")
		return
	}
	d.netMu.Unlock()

	// Relax peer backoffs so probe and replication loops reach throttled peers
	// quickly rather than waiting out long per-peer exponential-backoff windows.
	d.h.Node().RelaxHealthThrottle(healthRelaxCap)

	// Signal-ready gate: if ICE is configured but no hub is connected yet,
	// wait briefly so the published record includes live Signal URLs.
	if len(d.h.EffectiveICESignalURLs()) > 0 && len(d.h.ActiveSignalURLs()) == 0 {
		t := time.NewTimer(signalReadyTimeout)
		defer t.Stop()
		select {
		case <-d.signalReady:
			// Hub connected; proceed with fresh Signal URLs.
		case <-t.C:
			// No hub within timeout; publish now and let flush() republish later.
			d.pendingSignalRepublish.Store(true)
		case <-ctx.Done():
			return
		}
	}

	pubCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := d.publishNodeOnce(pubCtx); err != nil {
		d.log.Debug("force node republish", "err", err)
		d.netMu.Lock()
		d.deferredEndpointEval = true
		d.netMu.Unlock()
		return
	}
	d.netMu.Lock()
	d.deferredEndpointEval = false
	d.netMu.Unlock()
}

func (d *Daemon) tryRepublishAgent(ctx context.Context, aid a2al.Address) {
	// Per-AID try-lock: if a publish is already in flight for this agent,
	// skip rather than race (concurrent callers would compute the same nextSeq
	// and one would receive ErrStaleRecord, incorrectly marking the agent as migrated).
	actual, _ := d.agentPubLocks.LoadOrStore(aid, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	if !mu.TryLock() {
		return
	}
	defer mu.Unlock()

	// Re-read the entry so we always use the latest persisted seq, even when
	// the caller passed a value-copy snapshot (e.g. service.go snap := *e).
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	if e == nil || e.Seq == 0 {
		return
	}
	if !d.agentAliveForRepublish(e) {
		return
	}
	nextSeq := e.Seq + 1
	if err := d.h.PublishEndpointForAgent(ctx, aid, nextSeq, endpointRecordTTL); err != nil {
		if errors.Is(err, dht.ErrStaleRecord) {
			// Network has a higher seq: another node has taken over publishing for this agent.
			// Set zero sentinel to suppress both heartbeat and TCP-probe paths until the
			// agent re-contacts this node (touchHeartbeat will restore a real timestamp).
			d.heartbeatMu.Lock()
			if d.heartbeatAt == nil {
				d.heartbeatAt = make(map[a2al.Address]time.Time)
			}
			d.heartbeatAt[aid] = time.Time{}
			d.heartbeatMu.Unlock()
			d.log.Info("agent auto-republish stopped: stale record, agent may have migrated", "aid", aid.String())
		} else {
			d.log.Debug("agent auto-republish", "aid", aid.String(), "err", err)
		}
		return
	}

	d.regMu.Lock()
	defer d.regMu.Unlock()
	e2 := d.reg.Get(aid)
	if e2 == nil {
		return
	}
	e2.Seq = nextSeq
	if err := d.reg.Put(e2); err != nil {
		d.log.Warn("agent republish persist", "err", err)
		return
	}
	d.recordAgentPublishTime(aid)
	d.log.Debug("agent endpoint republished", "aid", aid.String(), "seq", nextSeq)

	// Also re-publish all registered services (topic records) for this agent.
	d.republishAgentServices(ctx, e2)
}

func (d *Daemon) republishAgentServices(ctx context.Context, e *registry.Entry) {
	// Re-publish RecType 0x02 sovereign profile alongside topic records.
	if pubErr := d.publishAgentProfile(ctx, e); pubErr != nil {
		d.log.Debug("agent profile republish", "aid", e.AID.String(), "err", pubErr)
	}
	if len(e.Services) == 0 {
		return
	}
	for _, svc := range e.Services {
		ttl := svc.TTL
		if ttl == 0 {
			ttl = 3600
		}
		base := protocol.TopicPayload{
			Name:      svc.Name,
			Protocols: svc.Protocols,
			Tags:      svc.Tags,
			Brief:     svc.Brief,
			Meta:      svc.Meta,
		}
		if err := d.h.RegisterTopicsForAgent(ctx, e.AID, []string{svc.Topic}, base, ttl); err != nil {
			d.log.Debug("agent service republish", "aid", e.AID.String(), "topic", svc.Topic, "err", err)
		} else {
			d.log.Debug("agent service republished", "aid", e.AID.String(), "topic", svc.Topic)
		}
	}
}

func (d *Daemon) runPeriodicRepublish(ctx context.Context) {
	if d.cfg.AutoPublish {
		d.netMu.Lock()
		if deferNow, reason := d.shouldDeferNodePublishLocked(d.now()); deferNow {
			d.netMu.Unlock()
			d.log.Debug("periodic node publish deferred", "reason", reason)
		} else {
			d.netMu.Unlock()
			pubCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			if err := d.publishNodeOnce(pubCtx); err != nil {
				d.log.Debug("periodic node publish", "err", err)
			}
			cancel()
		}
	}

	d.regMu.RLock()
	agents := d.reg.List()
	d.regMu.RUnlock()

	agCtx, agCancel := context.WithTimeout(ctx, 120*time.Second)
	defer agCancel()
	for _, e := range agents {
		d.tryRepublishAgent(agCtx, e.AID)
	}

	// Refresh supplemental bootstrap addresses and push locally-published records.
	if d.beacon != nil {
		d.beacon.RefreshAndStore(ctx, d.allAgentKeys())
	}
}

func (d *Daemon) initialAutoPublish(ctx context.Context) {
	seq, err := d.loadNodePublishState()
	if err != nil {
		d.log.Debug("node publish state load", "err", err)
	}
	d.nodePublishMu.Lock()
	d.nodePublishSeq = seq
	d.nodePublishMu.Unlock()

	if d.cfg.AutoPublish {
		pubCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		if err := d.publishNodeOnce(pubCtx); err != nil {
			d.log.Warn("initial node publish", "err", err)
		}
		cancel()

		// Recover from lost persistence: resolve own record from the DHT.
		// If the network already has a higher seq (e.g. from a previous run
		// whose state file was lost), republish at networkSeq+1 immediately so
		// our record is accepted without waiting for the old TTL to expire.
		go d.recoverSeqFromNetwork(ctx)

		// Republish agent services ~60 s after startup so gateway agents
		// (service_tcp reachable) recover without waiting for the first
		// periodic tick (30 min). Self-service agents still require a fresh
		// heartbeat before republish — no change in that behaviour.
		// Each agent gets a random cold-start jitter (0–30 s) to spread
		// publish traffic and avoid simultaneous bursts on restart.
		go func() {
			t := time.NewTimer(60 * time.Second)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			d.regMu.RLock()
			agents := d.reg.List()
			d.regMu.RUnlock()
			for _, e := range agents {
				e := e
				go func() {
					jitter := time.Duration(mrand.Int63n(int64(30 * time.Second)))
					jt := time.NewTimer(jitter)
					defer jt.Stop()
					select {
					case <-ctx.Done():
						return
					case <-jt.C:
					}
					d.tryRepublishAgent(ctx, e.AID)
				}()
			}
		}()
	} else {
		// Still capture fingerprint so endpoint-change detection works after user enables auto_publish.
		pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		ep, err := d.h.BuildEndpointPayload(pctx)
		cancel()
		if err == nil {
			d.publishMetaMu.Lock()
			d.lastEndpointsFP = endpointPayloadFingerprint(ep)
			d.publishMetaMu.Unlock()
		}
	}
}

// recoverSeqFromNetwork resolves the node's own AID from the DHT and, if the
// network holds a higher seq than our current local value (e.g. after losing
// the persistence file), immediately republishes at networkSeq+1 so the record
// is accepted by all peers without waiting for TTL expiry.
func (d *Daemon) recoverSeqFromNetwork(ctx context.Context) {
	// FindRecords checks the local store before querying the network, so without
	// real DHT peers the resolved record is our own just-written local entry —
	// not a true "network" value. Bail out early to avoid a spurious republish.
	if len(d.h.Node().BootstrapCandidateAddrs(1)) == 0 {
		return
	}

	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	er, err := d.h.Resolve(rctx, d.nodeAddr)
	if err != nil {
		// DHT lookup failed (e.g. no peers yet); nothing to recover.
		return
	}

	d.nodePublishMu.Lock()
	local := d.nodePublishSeq
	d.nodePublishMu.Unlock()

	if er.Seq <= local {
		// Network seq is not ahead; our initial publish already succeeded.
		return
	}

	// Network has a higher seq: update local state and republish.
	d.log.Info("seq recovery: network ahead, republishing", "network_seq", er.Seq, "local_seq", local)
	d.nodePublishMu.Lock()
	d.nodePublishSeq = er.Seq
	d.nodePublishMu.Unlock()

	pubCtx, pubCancel := context.WithTimeout(ctx, 90*time.Second)
	defer pubCancel()
	if err := d.publishNodeOnce(pubCtx); err != nil {
		d.log.Warn("seq recovery republish", "err", err)
	}
}

// publishNodeNowAsync publishes the node identity after enabling auto_publish (non-blocking).
func (d *Daemon) publishNodeNowAsync() {
	go func() {
		if !d.cfg.AutoPublish {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := d.publishNodeOnce(ctx); err != nil {
			d.log.Debug("async node publish", "err", err)
		}
	}()
}

// natProbePeriod is how often RunNATProbe is re-run in the main loop.
// Kept below probeResultTTL (30 min) so the classification never goes stale.
const natProbePeriod = 20 * time.Minute

func (d *Daemon) autoPublishMainLoop(ctx context.Context) {
	repub := time.NewTicker(republishPeriod)
	defer repub.Stop()
	watch := time.NewTicker(endpointWatchPeriod)
	defer watch.Stop()
	probe := time.NewTicker(natProbePeriod)
	defer probe.Stop()
	guard := time.NewTicker(guardTickPeriod)
	defer guard.Stop()
	anchor := time.NewTicker(anchorKeepalivePeriod)
	defer anchor.Stop()

	recoveryNotify := d.h.Node().RecoveryNotify()

	for {
		select {
		case <-ctx.Done():
			return
		case <-guard.C:
			d.handleGuardTick(ctx)
		case <-anchor.C:
			go d.runAnchorKeepalive(ctx)
		case <-repub.C:
			runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
			d.runPeriodicRepublish(runCtx)
			cancel()
		case <-watch.C:
			wctx, cancel := context.WithTimeout(ctx, 100*time.Second)
			d.maybeRepublishNodeOnEndpointChange(wctx)
			cancel()
		case <-probe.C:
			go func() {
				rbCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
				d.maybeRebootstrap(rbCtx)
				cancel()
				pCtx, cancel2 := context.WithTimeout(ctx, 20*time.Second)
				d.h.RunNATProbe(pCtx)
				cancel2()
				// Refresh routing hub candidates after NAT probe; cheap in-memory
				// scan. Only overwrites if no explicit config is set.
				d.h.SetRoutingHubCandidates(d.h.DeriveRoutingHubURLs(maxSignalCandidates))
			}()
		case <-recoveryNotify:
			// First successful RPC after a long outage: force-publish so
			// peers get a fresh record with current endpoint / Signal URLs,
			// then push updated records for all registered agents.
			go func() {
				rCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
				defer cancel()
				d.forcePublishNodeOnce(rCtx)
				d.regMu.RLock()
				agents := d.reg.List()
				d.regMu.RUnlock()
				for _, e := range agents {
					d.tryRepublishAgent(rCtx, e.AID)
				}
			}()
		}
	}
}

// runAnchorKeepalive pings up to 2 healthy routing-table peers.
//
// Purpose (dual):
//  1. Keep the local UDP NAT binding active by sending periodic outbound packets.
//  2. Collect observed_addr from PONG responses; natsense aggregates these and
//     the endpointWatchPeriod ticker triggers maybeRepublishNodeOnEndpointChange
//     if our external address has genuinely changed.
//
// Skipped when the local node has a direct public WAN binding: NAT mappings do
// not apply and observed_addr changes are handled by netchange.go instead.
// Errors are intentionally ignored: this is best-effort keep-alive.
func (d *Daemon) runAnchorKeepalive(ctx context.Context) {
	if d.h.Sense().IsBindPublic() {
		return
	}
	addrs := d.h.Node().BootstrapCandidateAddrs(4)
	sent := 0
	for _, addr := range addrs {
		if sent >= 2 {
			break
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, _ = d.h.Node().PingIdentity(pctx, addr)
		cancel()
		sent++
	}
}
