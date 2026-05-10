// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"log/slog"
)

// newComponentFilterHandler wraps base with a handler that lets DEBUG-level
// records through when they carry a "component" attribute matching one of
// the names in comps, even when base would suppress them (e.g. base level
// is Info). Returns base unchanged when comps is empty.
//
// Usage at call sites:
//
//	slog.Debug("msg", "component", "ice", "key", val)
//	h.log.Debug("msg", "component", "punch", "key", val)
//
// Recognized component names (by convention, not enforced here):
// "ice", "punch", "natsense".
func newComponentFilterHandler(base slog.Handler, comps []string) slog.Handler {
	if len(comps) == 0 {
		return base
	}
	m := make(map[string]struct{}, len(comps))
	for _, c := range comps {
		m[c] = struct{}{}
	}
	return &componentFilterHandler{base: base, comps: m}
}

type componentFilterHandler struct {
	base    slog.Handler
	comps   map[string]struct{}
	preComp string // component value pre-attached via WithAttrs
}

// Enabled returns true for Debug when any components are configured so that
// records reach Handle for component inspection.
// For Info and above, delegates to the base handler.
func (h *componentFilterHandler) Enabled(_ context.Context, level slog.Level) bool {
	if level < slog.LevelInfo {
		// Let all Debug records through to Handle; Handle re-applies the gate.
		return true
	}
	return h.base.Enabled(context.Background(), level)
}

// Handle passes the record to base if:
//   - level ≥ Info (base gate applies normally), OR
//   - level == Debug AND the record has a "component" attr matching comps, OR
//   - level == Debug AND base would normally emit it (log_level=debug).
func (h *componentFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelInfo {
		return h.base.Handle(ctx, r)
	}

	// Debug path: find component attr (pre-attached or inline).
	comp := h.preComp
	if comp == "" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "component" {
				comp = a.Value.String()
				return false
			}
			return true
		})
	}

	if comp != "" {
		if _, ok := h.comps[comp]; ok {
			return h.base.Handle(ctx, r)
		}
	}
	// No matching component: apply normal base level gate.
	if h.base.Enabled(ctx, r.Level) {
		return h.base.Handle(ctx, r)
	}
	return nil
}

func (h *componentFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	preComp := h.preComp
	for _, a := range attrs {
		if a.Key == "component" {
			preComp = a.Value.String()
			break
		}
	}
	return &componentFilterHandler{
		base:    h.base.WithAttrs(attrs),
		comps:   h.comps,
		preComp: preComp,
	}
}

func (h *componentFilterHandler) WithGroup(name string) slog.Handler {
	return &componentFilterHandler{
		base:    h.base.WithGroup(name),
		comps:   h.comps,
		preComp: h.preComp,
	}
}
