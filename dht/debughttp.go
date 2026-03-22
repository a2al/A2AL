package dht

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/a2al/a2al/routing"
)

// debugIdentityJSON is the payload for GET /debug/identity (spec §3.6).
type debugIdentityJSON struct {
	Address   string `json:"address"`
	NodeIDHex string `json:"node_id_hex"`
	LocalAddr string `json:"local_addr"`
}

// debugRoutingJSON is the payload for GET /debug/routing (spec §3.6).
type debugRoutingJSON struct {
	SelfNodeIDHex string                 `json:"self_node_id_hex"`
	Peers         []routing.PeerDebugRow `json:"peers"`
	TotalPeers    int                    `json:"total_peers"`
}

// debugStatsJSON is the payload for GET /debug/stats (spec §3.6).
type debugStatsJSON struct {
	RxPackets uint64 `json:"rx_packets_verified"`
	TxPackets uint64 `json:"tx_packets"`
	RPCOK     uint64 `json:"rpc_completed"`
}

func (n *Node) tabDebugPeers() []routing.PeerDebugRow {
	n.tabMu.RLock()
	defer n.tabMu.RUnlock()
	return n.table.DebugPeerRows()
}

// DebugHTTPHandler returns read-only /debug/* handlers for mounting on an existing server (spec §3.6).
func (n *Node) DebugHTTPHandler() http.Handler { return n.debugMux() }

func (n *Node) debugMux() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/debug/identity", n.serveDebugIdentity)
	m.HandleFunc("/debug/routing", n.serveDebugRouting)
	m.HandleFunc("/debug/store", n.serveDebugStore)
	m.HandleFunc("/debug/stats", n.serveDebugStats)
	return m
}

func (n *Node) serveDebugIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(debugIdentityJSON{
		Address:   n.addr.String(),
		NodeIDHex: hex.EncodeToString(n.nid[:]),
		LocalAddr: n.tr.LocalAddr().String(),
	})
}

func (n *Node) serveDebugRouting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	peers := n.tabDebugPeers()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(debugRoutingJSON{
		SelfNodeIDHex: hex.EncodeToString(n.nid[:]),
		Peers:         peers,
		TotalPeers:    len(peers),
	})
}

func (n *Node) serveDebugStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	now := time.Now()
	recs := n.store.DebugRecords(now)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(recs)
}

func (n *Node) serveDebugStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(debugStatsJSON{
		RxPackets: n.statsRx.Load(),
		TxPackets: n.statsTx.Load(),
		RPCOK:     n.statsRPC.Load(),
	})
}

// StartDebugHTTP listens on addr and serves read-only /debug/* JSON (spec §3.6).
// Typical addr: "127.0.0.1:2634". stop shuts the server down (idempotent).
func (n *Node) StartDebugHTTP(addr string) (stop func(), err error) {
	if n == nil {
		return nil, errors.New("dht: nil node")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           n.debugMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}, nil
}

// DebugHTTPAddr is a convenience for "127.0.0.1:2634" (spec §3.6).
const DebugHTTPAddr = "127.0.0.1:2634"
