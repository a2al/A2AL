// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/a2al/a2al"
)

const (
	// fetchMaxBody caps the response body buffered in daemon memory.
	fetchMaxBody = 4 << 20 // 4 MiB

	// fetchStreamTimeout is the per-stream HTTP round-trip deadline.
	fetchStreamTimeout = 30 * time.Second
)

// fetchReq is the body for POST /fetch/{aid} and the a2al_fetch MCP tool.
type fetchReq struct {
	// LocalAID selects which registered agent identity to dial from.
	// Defaults to the node identity when omitted.
	LocalAID   string              `json:"local_aid,omitempty"`
	Method     string              `json:"method,omitempty"`    // default GET
	Path       string              `json:"path"`                // e.g. "/api/status"
	Headers    map[string][]string `json:"headers,omitempty"`
	BodyBase64 string              `json:"body_base64,omitempty"`
}

// fetchResp is the structured response returned by execFetch.
type fetchResp struct {
	Status    int                 `json:"status"`
	Headers   map[string][]string `json:"headers,omitempty"`
	// Body is the response body, base64-encoded.
	Body      string              `json:"body"`
	// Truncated is true when the body exceeded fetchMaxBody and was cut off.
	Truncated bool                `json:"truncated,omitempty"`
}

// preparedFetch holds the normalised values derived from a fetchReq.
type preparedFetch struct {
	method string
	path   string
	host   string // non-empty when caller supplied a Host override
	body   io.Reader
}

// prepareFetch validates and normalises a fetchReq into a preparedFetch.
func prepareFetch(req fetchReq) (preparedFetch, error) {
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	path := req.Path
	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	var bodyReader io.Reader
	if req.BodyBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err != nil {
			return preparedFetch{}, errors.New("invalid body_base64")
		}
		bodyReader = bytes.NewReader(raw)
	}

	// Extract Host override so callers can set httpReq.Host correctly.
	// net/http ignores Header["Host"] — it must be set on Request.Host.
	var host string
	if vals, ok := req.Headers["Host"]; ok && len(vals) > 0 {
		host = vals[0]
	}

	return preparedFetch{method: method, path: path, host: host, body: bodyReader}, nil
}

// applyHeaders copies req.Headers onto an http.Request, skipping the Host
// key (which is handled separately via Request.Host).
func applyHeaders(httpReq *http.Request, headers map[string][]string) {
	for k, vals := range headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}
}

// collectHeaders builds a map[string][]string from an http.Response header,
// preserving all values for multi-value fields (e.g. Set-Cookie, Vary).
func collectHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// readBody reads up to fetchMaxBody bytes and signals truncation.
func readBody(r io.Reader) ([]byte, bool, error) {
	limited := io.LimitReader(r, fetchMaxBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if len(data) > fetchMaxBody {
		return data[:fetchMaxBody], true, nil
	}
	return data, false, nil
}

// execFetch makes a single HTTP request to remoteAID's service.
//
// If remoteAID is registered on this daemon with a known service_tcp address,
// the request is made directly via TCP without going through QUIC (local
// short-circuit). Otherwise the request travels through the Tangled Network:
// resolve → acquire pooled QUIC connection → open stream → HTTP/1.1.
//
// On a dead-connection error the pool evicts the entry automatically; execFetch
// retries once with a fresh connection before returning an error.
func (d *Daemon) execFetch(ctx context.Context, localAID, remoteAID a2al.Address, req fetchReq) (fetchResp, error) {
	// Local short-circuit: if remoteAID is a locally registered agent with a
	// known service_tcp, skip QUIC entirely. d.reg only contains agents
	// explicitly registered with this daemon, so there are no false positives.
	d.regMu.RLock()
	localEntry := d.reg.Get(remoteAID)
	d.regMu.RUnlock()
	if localEntry != nil && localEntry.ServiceTCP != "" {
		return execFetchDirect(ctx, localEntry.ServiceTCP, req)
	}

	// Resolve remote endpoint (20 s budget; shares the caller's context).
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	er, err := d.h.Resolve(rctx, remoteAID)
	rcancel()
	if err != nil {
		if d.beacon != nil {
			er, err = d.resolveFromBeacon(ctx, remoteAID)
		}
		if err != nil {
			return fetchResp{}, errResolve
		}
	}

	// Inner helper: acquire a connection and do the HTTP exchange over a stream.
	// Returns errConnectQUIC when the connection appears dead so the caller can
	// retry once.
	doFetch := func() (fetchResp, error) {
		conn, _, err := d.connPool.acquire(ctx, localAID, remoteAID, er, false)
		if err != nil {
			return fetchResp{}, errConnectQUIC
		}

		sctx, scancel := context.WithTimeout(ctx, fetchStreamTimeout)
		defer scancel()

		stream, err := conn.OpenStreamSync(sctx)
		if err != nil {
			d.log.Debug("fetch: open stream failed (dead conn?)", "remote", remoteAID.String(), "err", err)
			return fetchResp{}, errConnectQUIC
		}
		defer func() {
			stream.CancelRead(0)
			_ = stream.Close()
		}()

		if dl, ok := sctx.Deadline(); ok {
			_ = stream.SetDeadline(dl)
		}
		return doHTTPOverStream(stream, req)
	}

	resp, err := doFetch()
	if errors.Is(err, errConnectQUIC) {
		// Dead connection: the pool will evict it on the next acquire call.
		// Retry once; the second acquire will re-dial.
		d.log.Debug("fetch: retrying after dead connection", "remote", remoteAID.String())
		resp, err = doFetch()
	}
	return resp, err
}

// execFetchDirect makes an HTTP request directly to a local service_tcp address,
// bypassing QUIC entirely. Used when remoteAID is a locally registered agent.
func execFetchDirect(ctx context.Context, serviceTCP string, req fetchReq) (fetchResp, error) {
	pf, err := prepareFetch(req)
	if err != nil {
		return fetchResp{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, pf.method, "http://"+serviceTCP+pf.path, pf.body)
	if err != nil {
		return fetchResp{}, err
	}
	if pf.host != "" {
		httpReq.Host = pf.host
	}
	applyHeaders(httpReq, req.Headers)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fetchResp{}, err
	}
	defer resp.Body.Close()

	body, truncated, err := readBody(resp.Body)
	if err != nil {
		return fetchResp{}, err
	}
	return fetchResp{
		Status:    resp.StatusCode,
		Headers:   collectHeaders(resp.Header),
		Body:      base64.StdEncoding.EncodeToString(body),
		Truncated: truncated,
	}, nil
}

// doHTTPOverStream writes an HTTP/1.1 request to stream and reads the response.
// The stream carries raw HTTP/1.1 bytes; the remote daemon's gateway bridges it
// to the local service_tcp transparently.
func doHTTPOverStream(stream io.ReadWriter, req fetchReq) (fetchResp, error) {
	pf, err := prepareFetch(req)
	if err != nil {
		return fetchResp{}, err
	}

	// Build a minimal HTTP/1.1 request. The fake host is irrelevant; the
	// connection is already routed to the correct remote service via QUIC.
	httpReq, err := http.NewRequest(pf.method, "http://a2al-agent"+pf.path, pf.body)
	if err != nil {
		return fetchResp{}, err
	}
	if pf.host != "" {
		httpReq.Host = pf.host
	}
	httpReq.Header.Set("Connection", "close")
	applyHeaders(httpReq, req.Headers)

	if err := httpReq.Write(stream); err != nil {
		return fetchResp{}, err
	}

	resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 32*1024), httpReq)
	if err != nil {
		return fetchResp{}, err
	}
	defer resp.Body.Close()

	body, truncated, err := readBody(resp.Body)
	if err != nil {
		return fetchResp{}, err
	}
	return fetchResp{
		Status:    resp.StatusCode,
		Headers:   collectHeaders(resp.Header),
		Body:      base64.StdEncoding.EncodeToString(body),
		Truncated: truncated,
	}, nil
}

// ── HTTP handler ─────────────────────────────────────────────────────────────

func (d *Daemon) handleFetch(w http.ResponseWriter, r *http.Request) {
	remoteAID, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}

	var req fetchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	localAID, err := resolveLocalAID(req.LocalAID, d.nodeAddr)
	if err != nil {
		http.Error(w, `{"error":"bad local_aid"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result, err := d.execFetch(ctx, localAID, remoteAID, req)
	if err != nil {
		switch {
		case errors.Is(err, errResolve):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "resolve failed"})
		case errors.Is(err, errConnectQUIC):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "connect failed"})
		default:
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, result)
}

// resolveLocalAID parses aidStr when non-empty, otherwise returns the default.
func resolveLocalAID(aidStr string, defaultAddr a2al.Address) (a2al.Address, error) {
	if aidStr == "" {
		return defaultAddr, nil
	}
	return a2al.ParseAddress(aidStr)
}
