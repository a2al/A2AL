// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
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
	if hbOK && time.Since(t) < heartbeatTTL {
		return true
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
		d.log.Debug("agent auto-republish", "aid", e.AID.String(), "err", err)
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
