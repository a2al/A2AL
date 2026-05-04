// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

const agentProfileTTL uint32 = 3600

// agentProfileReq is the request body for POST /agents/{aid}/profile.
type agentProfileReq struct {
	Name       string         `json:"name,omitempty"`
	Brief      string         `json:"brief,omitempty"`
	Protocols  []string       `json:"protocols,omitempty"`
	Skills     []string       `json:"skills,omitempty"`
	CardHash   string         `json:"card_hash,omitempty"` // hex or base64
	Modalities []string       `json:"modalities,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
}

// buildAgentProfilePayload assembles an AgentProfilePayload from an Entry.
// Profile fields (explicit) take precedence field-by-field over values inferred
// from registered Services. Returns (payload, false) when there is nothing to publish.
func buildAgentProfilePayload(e *registry.Entry) (protocol.AgentProfilePayload, bool) {
	p := protocol.AgentProfilePayload{Version: 1}
	hasData := false

	ov := e.Profile // may be nil

	// Name
	if ov != nil && ov.Name != "" {
		p.Name = ov.Name
	}
	if p.Name != "" {
		hasData = true
	}

	// Brief
	if ov != nil && ov.Brief != "" {
		p.Brief = ov.Brief
	}
	if p.Brief != "" {
		hasData = true
	}

	// Protocols: explicit wins; fallback: union from Services
	if ov != nil && len(ov.Protocols) > 0 {
		p.Protocols = append([]string(nil), ov.Protocols...)
	} else if len(e.Services) > 0 {
		seen := make(map[string]struct{})
		for _, svc := range e.Services {
			for _, pr := range svc.Protocols {
				if _, ok := seen[pr]; !ok {
					seen[pr] = struct{}{}
					p.Protocols = append(p.Protocols, pr)
				}
			}
		}
	}
	if len(p.Protocols) > 0 {
		hasData = true
	}

	// Skills: explicit wins; fallback: topic names from Services
	if ov != nil && len(ov.Skills) > 0 {
		p.Skills = append([]string(nil), ov.Skills...)
	} else if len(e.Services) > 0 {
		for _, svc := range e.Services {
			p.Skills = append(p.Skills, svc.Topic)
		}
	}
	if len(p.Skills) > 0 {
		hasData = true
	}

	// CardHash
	if ov != nil && len(ov.CardHash) > 0 {
		p.CardHash = append([]byte(nil), ov.CardHash...)
		hasData = true
	}

	// Modalities
	if ov != nil && len(ov.Modalities) > 0 {
		p.Modalities = append([]string(nil), ov.Modalities...)
		hasData = true
	}

	// Meta
	if ov != nil && len(ov.Meta) > 0 {
		p.Meta = ov.Meta
		hasData = true
	}

	if !hasData {
		return protocol.AgentProfilePayload{}, false
	}
	return p, true
}

// buildAgentProfileRecord builds and signs a RecType 0x02 SignedRecord from e.
// Must be called while the caller holds a stable view of e (e.g. under regMu).
// Returns (nil, nil) when there is nothing to publish.
func (d *Daemon) buildAgentProfileRecord(e *registry.Entry) (*protocol.SignedRecord, error) {
	if len(e.DelegationCBOR) == 0 {
		return nil, nil
	}
	p, ok := buildAgentProfilePayload(e)
	if !ok {
		return nil, nil
	}
	payload, err := protocol.MarshalAgentProfilePayload(p)
	if err != nil {
		// ErrPayloadApproachingLimit is advisory: payload was still returned, continue.
		if !errors.Is(err, protocol.ErrPayloadApproachingLimit) {
			return nil, err
		}
		d.log.Warn("agent profile payload approaching size limit", "aid", e.AID.String(), "err", err)
	}
	now := time.Now()
	rec, err := protocol.SignRecordDelegated(
		e.OpPriv, e.DelegationCBOR, e.AID,
		protocol.RecTypeAgentProfile,
		payload,
		uint64(now.UnixNano()),
		uint64(now.Unix()),
		agentProfileTTL,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// publishAgentProfile is a synchronous convenience wrapper used when the caller
// already holds a stable view of e (e.g. republishAgentServices under regMu).
func (d *Daemon) publishAgentProfile(ctx context.Context, e *registry.Entry) error {
	rec, err := d.buildAgentProfileRecord(e)
	if err != nil {
		d.log.Warn("agent profile build", "aid", e.AID.String(), "err", err)
		return err
	}
	if rec == nil {
		return nil
	}
	return d.h.PublishRecord(ctx, *rec)
}

// execAgentSetProfile stores the profile override and immediately publishes 0x02.
func (d *Daemon) execAgentSetProfile(_ context.Context, aidStr string, req agentProfileReq) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}

	ov := &registry.ProfileOverride{
		Name:       req.Name,
		Brief:      req.Brief,
		Protocols:  req.Protocols,
		Skills:     req.Skills,
		Modalities: req.Modalities,
		Meta:       req.Meta,
	}
	if req.CardHash != "" {
		raw, decErr := parseCardHash(req.CardHash)
		if decErr != nil {
			return decErr
		}
		ov.CardHash = raw
	}

	d.regMu.Lock()
	e := d.reg.Get(aid)
	if e == nil {
		d.regMu.Unlock()
		return errNotFound
	}
	e.Profile = ov
	if err := d.reg.Put(e); err != nil {
		d.regMu.Unlock()
		return err
	}
	// Build record under lock so goroutine only touches an immutable value.
	rec, recErr := d.buildAgentProfileRecord(e)
	d.regMu.Unlock()

	go func() {
		if recErr != nil {
			d.log.Warn("agent profile build", "aid", aid.String(), "err", recErr)
			return
		}
		if rec != nil {
			if pubErr := d.h.PublishRecord(context.Background(), *rec); pubErr != nil {
				d.log.Warn("agent profile publish", "aid", aid.String(), "err", pubErr)
			}
		}
	}()
	return nil
}

// execAgentDeleteProfile removes the profile override and republishes 0x02 from
// inferred service data only (or skips if no services are registered).
func (d *Daemon) execAgentDeleteProfile(_ context.Context, aidStr string) error {
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		return errBadAID
	}

	d.regMu.Lock()
	e := d.reg.Get(aid)
	if e == nil {
		d.regMu.Unlock()
		return errNotFound
	}
	e.Profile = nil
	if err := d.reg.Put(e); err != nil {
		d.regMu.Unlock()
		return err
	}
	rec, recErr := d.buildAgentProfileRecord(e)
	d.regMu.Unlock()

	go func() {
		if recErr != nil {
			d.log.Warn("agent profile build after delete", "aid", aid.String(), "err", recErr)
			return
		}
		if rec != nil {
			if pubErr := d.h.PublishRecord(context.Background(), *rec); pubErr != nil {
				d.log.Warn("agent profile publish after delete", "aid", aid.String(), "err", pubErr)
			}
		}
	}()
	return nil
}

// parseCardHash decodes a hex (64 chars) or standard-base64 (44 chars) SHA-256 hash.
// Returns an error if the decoded value is not exactly 32 bytes.
func parseCardHash(s string) ([]byte, error) {
	var raw []byte
	var err error
	switch len(s) {
	case 64:
		raw, err = hex.DecodeString(s)
	case 44:
		raw, err = base64.StdEncoding.DecodeString(s)
	default:
		return nil, errors.New("card_hash must be 64-char hex or 44-char base64 (SHA-256)")
	}
	if err != nil {
		return nil, errors.New("card_hash decode failed: " + err.Error())
	}
	if len(raw) != 32 {
		return nil, errors.New("card_hash must be a 32-byte SHA-256 digest")
	}
	return raw, nil
}
