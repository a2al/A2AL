// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"encoding/json"
	"net/http"
)

type debugHostJSON struct {
	Address      string   `json:"address"`
	DHTAddr      string   `json:"dht_addr"`
	QUICAddr     string   `json:"quic_addr"`
	Agents       []string `json:"agents"`
	NATType      uint8    `json:"nat_type"`
	NATTypeLabel string   `json:"nat_type_label"`
	ObservedHost string   `json:"observed_host,omitempty"`
	ObservedPort uint16   `json:"observed_port,omitempty"`
	MinObserved  int      `json:"min_observed_peers"`
}

var natLabels = [...]string{"unknown", "full_cone", "restricted", "port_restricted", "symmetric"}

func natLabel(t uint8) string {
	if int(t) < len(natLabels) {
		return natLabels[t]
	}
	return "unknown"
}

// DebugHTTPHandler returns an http.Handler serving /debug/host (Phase 2 state)
// and delegates /debug/identity, /debug/routing, /debug/store, /debug/stats
// to the underlying DHT node.
func (h *Host) DebugHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	// DHT-level debug endpoints.
	dhtHandler := h.node.DebugHTTPHandler()
	mux.Handle("/debug/identity", dhtHandler)
	mux.Handle("/debug/routing", dhtHandler)
	mux.Handle("/debug/store", dhtHandler)
	mux.Handle("/debug/stats", dhtHandler)
	// Host-level (Phase 2) endpoint.
	mux.HandleFunc("/debug/host", h.serveDebugHost)
	return mux
}

func (h *Host) serveDebugHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agents := h.RegisteredAgents()
	agentStrs := make([]string, len(agents))
	for i, a := range agents {
		agentStrs[i] = a.String()
	}
	natT := h.sense.InferNATType()
	obsHost, obsPort, _ := h.sense.TrustedUDP()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(debugHostJSON{
		Address:      h.addr.String(),
		DHTAddr:      h.DHTLocalAddr().String(),
		QUICAddr:     h.QUICLocalAddr().String(),
		Agents:       agentStrs,
		NATType:      natT,
		NATTypeLabel: natLabel(natT),
		ObservedHost: obsHost,
		ObservedPort: obsPort,
		MinObserved:  h.sense.MinAgreeing(),
	})
}
