// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

const (
	endpointRecordTTL   = uint32(3600)
	republishPeriod     = time.Duration(endpointRecordTTL/2) * time.Second // 30m
	endpointWatchPeriod = 60 * time.Second
	heartbeatTTL        = time.Duration(endpointRecordTTL) * time.Second
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
	for _, x := range ep.Endpoints {
		b.WriteString(x)
		b.WriteByte('|')
	}
	b.WriteString(ep.Signal)
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
	d.publishMetaMu.Lock()
	d.nodeLastPublish = time.Now()
	d.publishMetaMu.Unlock()
}

func (d *Daemon) publishNodeOnce(ctx context.Context) error {
	d.nodePublishMu.Lock()
	nextSeq := d.nodePublishSeq + 1
	d.nodePublishMu.Unlock()

	if err := d.h.PublishEndpoint(ctx, nextSeq, endpointRecordTTL); err != nil {
		return err
	}

	d.nodePublishMu.Lock()
	d.nodePublishSeq = nextSeq
	d.nodePublishMu.Unlock()

	if err := d.saveNodePublishState(); err != nil {
		d.log.Warn("node publish state save", "err", err)
	}

	d.recordNodePublishTime()

	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	ep, err := d.h.BuildEndpointPayload(pctx)
	cancel()
	if err == nil {
		d.publishMetaMu.Lock()
		d.lastEndpointsFP = endpointPayloadFingerprint(ep)
		d.publishMetaMu.Unlock()
	}

	d.log.Info("node endpoint published to DHT", "seq", nextSeq)
	return nil
}

func (d *Daemon) maybeRepublishNodeOnEndpointChange(ctx context.Context) {
	if !d.cfg.AutoPublish {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	ep, err := d.h.BuildEndpointPayload(pctx)
	cancel()
	if err != nil {
		return
	}
	fp := endpointPayloadFingerprint(ep)

	d.publishMetaMu.Lock()
	prev := d.lastEndpointsFP
	d.publishMetaMu.Unlock()

	if prev != "" && fp != prev {
		pubCtx, pubCancel := context.WithTimeout(ctx, 90*time.Second)
		err := d.publishNodeOnce(pubCtx)
		pubCancel()
		if err != nil {
			d.log.Debug("node republish on endpoint change", "err", err)
		}
	}
}

func (d *Daemon) tryRepublishAgent(ctx context.Context, e *registry.Entry) {
	if e.Seq == 0 {
		return
	}
	if !d.agentAliveForRepublish(e) {
		return
	}
	nextSeq := e.Seq + 1
	if err := d.h.PublishEndpointForAgent(ctx, e.AID, nextSeq, endpointRecordTTL); err != nil {
		if errors.Is(err, dht.ErrStaleRecord) {
			// Network has a higher seq: another node has taken over publishing for this agent.
			// Set zero sentinel to suppress both heartbeat and TCP-probe paths until the
			// agent re-contacts this node (touchHeartbeat will restore a real timestamp).
			d.heartbeatMu.Lock()
			if d.heartbeatAt == nil {
				d.heartbeatAt = make(map[a2al.Address]time.Time)
			}
			d.heartbeatAt[e.AID] = time.Time{}
			d.heartbeatMu.Unlock()
			d.log.Info("agent auto-republish stopped: stale record, agent may have migrated", "aid", e.AID.String())
		} else {
			d.log.Debug("agent auto-republish", "aid", e.AID.String(), "err", err)
		}
		return
	}

	d.regMu.Lock()
	defer d.regMu.Unlock()
	e2 := d.reg.Get(e.AID)
	if e2 == nil {
		return
	}
	e2.Seq = nextSeq
	if err := d.reg.Put(e2); err != nil {
		d.log.Warn("agent republish persist", "err", err)
		return
	}
	d.recordAgentPublishTime(e.AID)
	d.log.Debug("agent endpoint republished", "aid", e.AID.String(), "seq", nextSeq)

	// Also re-publish all registered services (topic records) for this agent.
	d.republishAgentServices(ctx, e2)
}

func (d *Daemon) republishAgentServices(ctx context.Context, e *registry.Entry) {
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
		pubCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		if err := d.publishNodeOnce(pubCtx); err != nil {
			d.log.Debug("periodic node publish", "err", err)
		}
		cancel()
	}

	d.regMu.RLock()
	agents := d.reg.List()
	d.regMu.RUnlock()

	agCtx, agCancel := context.WithTimeout(ctx, 120*time.Second)
	defer agCancel()
	for _, e := range agents {
		d.tryRepublishAgent(agCtx, e)
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
		go func() {
			t := time.NewTimer(60 * time.Second)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			rctx, cancel := context.WithTimeout(ctx, 120*time.Second)
			defer cancel()
			d.regMu.RLock()
			agents := d.reg.List()
			d.regMu.RUnlock()
			for _, e := range agents {
				d.tryRepublishAgent(rctx, e)
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

func (d *Daemon) autoPublishMainLoop(ctx context.Context) {
	repub := time.NewTicker(republishPeriod)
	defer repub.Stop()
	watch := time.NewTicker(endpointWatchPeriod)
	defer watch.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-repub.C:
			runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
			d.runPeriodicRepublish(runCtx)
			cancel()
		case <-watch.C:
			wctx, cancel := context.WithTimeout(ctx, 100*time.Second)
			d.maybeRepublishNodeOnEndpointChange(wctx)
			cancel()
		}
	}
}
