// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package aidproxy implements the AID Resource Addressing Gateway.
//
// It exposes an [Handler] that translates
//
//	http://127.0.0.1:2121/aid/{address}/{path...}
//
// URLs into outbound connections to the named AID, streaming raw HTTP/1.1
// over the transport layer (QUIC stream for remote AIDs, direct TCP for
// locally registered agents).
//
// The handler is mounted at /aid/ outside the daemon's main middleware chain
// so that arbitrary Content-Types and large request bodies are supported.
package aidproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a2al/a2al"
)

// Resolver maps an address string to an [a2al.Address].
// Implementations may support raw AID strings, DNS TXT records, or other
// naming systems. Multiple resolvers can be composed with [Chain].
type Resolver interface {
	Resolve(ctx context.Context, address string) (a2al.Address, error)
}

// Dialer opens a bidirectional stream to a remote AID.
//
// The returned [io.ReadWriteCloser] carries raw HTTP/1.1 bytes:
//   - For remote AIDs: a QUIC stream through the Tangled Network.
//   - For locally registered AIDs: a direct TCP connection to service_tcp.
//
// The caller is responsible for closing the returned stream.
type Dialer interface {
	Dial(ctx context.Context, remote a2al.Address) (io.ReadWriteCloser, error)
}

// Chain tries each Resolver in order, returning the first successful result.
type Chain []Resolver

// Resolve implements [Resolver] by trying each resolver in sequence.
func (c Chain) Resolve(ctx context.Context, address string) (a2al.Address, error) {
	var last error
	for _, r := range c {
		addr, err := r.Resolve(ctx, address)
		if err == nil {
			return addr, nil
		}
		last = err
	}
	if last != nil {
		return a2al.Address{}, last
	}
	return a2al.Address{}, errors.New("aidproxy: empty resolver chain")
}

// RawAIDResolver resolves raw AID strings (the primary Phase 1 resolver).
// Later phases add DNS TXT bridging and DHT name resolution as additional
// links in a [Chain].
type RawAIDResolver struct{}

// Resolve parses a raw AID string.
func (RawAIDResolver) Resolve(_ context.Context, address string) (a2al.Address, error) {
	return a2al.ParseAddress(address)
}

// hopByHopHeaders are stripped before forwarding per RFC 7230 §6.1.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailers", "Transfer-Encoding", "Upgrade",
}

// Handler is the AID Resource Addressing Gateway [http.Handler].
//
// It parses the AID address from the URL path, resolves it, dials a stream
// to the remote AID, and bidirectionally proxies the raw HTTP/1.1 exchange.
type Handler struct {
	resolver Resolver
	dialer   Dialer
	log      *slog.Logger
}

// New creates a [Handler] with the given resolver, dialer, and logger.
// If log is nil, [slog.Default] is used.
func New(resolver Resolver, dialer Dialer, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{resolver: resolver, dialer: dialer, log: log}
}

// NewChain constructs a [Chain] from the given resolvers.
func NewChain(resolvers ...Resolver) Chain {
	return Chain(resolvers)
}

// dialTimeout is the deadline for the Dial phase (resolve + connect + open
// stream). It is deliberately separate from the stream I/O phase, which has
// no hard timeout so that streaming responses are not cut off mid-transfer.
const dialTimeout = 30 * time.Second

// ServeHTTP handles requests of the form /aid/{address}[/{path}[?{query}]].
//
// URL structure:
//
//	/aid/{address}[/{path}[?{query}]]
//
// {address} is resolved via the Resolver chain to an [a2al.Address].
// The request is then forwarded over the stream with its original method,
// headers, and body. The response is streamed back verbatim.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CONNECT uses authority-form URLs incompatible with /aid/{address}/...
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT not supported", http.StatusMethodNotAllowed)
		return
	}

	// Use EscapedPath so that percent-encoded slashes within the resource
	// path (e.g. /files/a%2Fb) are preserved and not prematurely decoded.
	escaped := r.URL.EscapedPath()
	rest := strings.TrimPrefix(escaped, "/aid/")
	addrEscaped, tail, _ := strings.Cut(rest, "/")

	// Unescape only the address portion; the resource path is forwarded verbatim.
	addrStr, err := url.PathUnescape(addrEscaped)
	if err != nil {
		http.Error(w, "bad aid address encoding", http.StatusBadRequest)
		return
	}
	resourcePath := "/" + tail
	if r.URL.RawQuery != "" {
		resourcePath += "?" + r.URL.RawQuery
	}

	// Resolve address.
	remote, err := h.resolver.Resolve(r.Context(), addrStr)
	if err != nil {
		h.log.Debug("aidproxy: resolve failed", "address", addrStr, "err", err)
		http.Error(w, "bad aid address", http.StatusBadRequest)
		return
	}

	// Phase 1: Dial with a bounded timeout.
	// dialCtx is cancelled as soon as Dial returns so that the stream I/O
	// phase is not bound to a hard deadline (spec: no hard timeout on stream).
	dialCtx, dialCancel := context.WithTimeout(r.Context(), dialTimeout)
	stream, dialErr := h.dialer.Dial(dialCtx, remote)
	dialCancel()
	if dialErr != nil {
		h.log.Debug("aidproxy: dial failed", "remote", remote.String(), "err", dialErr)
		http.Error(w, "connect failed", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Phase 2: Stream I/O — no hard timeout.
	// Client disconnect is detected via w.Write errors in io.Copy below;
	// QUIC connection idle timeout (90 s) bounds the remote-hang case.

	// Build the outbound HTTP/1.1 request.
	// Using addrStr as the URL host makes it the Host header, replacing the
	// original r.Host (127.0.0.1:2121) with the AID's logical identity.
	outReq, err := http.NewRequest(r.Method, "http://"+addrStr+resourcePath, r.Body)
	if err != nil {
		h.log.Debug("aidproxy: build request failed", "err", err)
		http.Error(w, "bad request", http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()
	// Strip hop-by-hop headers before forwarding (RFC 7230 §6.1).
	for _, hdr := range hopByHopHeaders {
		outReq.Header.Del(hdr)
	}
	// Re-add Connection: close so the remote HTTP/1.1 server treats this as a
	// single-request connection and closes the stream after the response.
	outReq.Header.Set("Connection", "close")
	// Preserve Content-Length from the original request so the remote server
	// knows the body size and does not require chunked transfer encoding.
	outReq.ContentLength = r.ContentLength

	// Write the request to the stream.
	if err := outReq.Write(stream); err != nil {
		h.log.Debug("aidproxy: upstream write failed", "remote", remote.String(), "err", err)
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	// Read the response from the stream.
	resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 32*1024), outReq)
	if err != nil {
		h.log.Debug("aidproxy: upstream read failed", "remote", remote.String(), "err", err)
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward response headers, stripping hop-by-hop.
	// Note: http.ReadResponse already moves Transfer-Encoding and
	// Content-Length out of resp.Header into struct fields, so those Del
	// calls below are no-ops but are kept for completeness.
	for _, hdr := range hopByHopHeaders {
		resp.Header.Del(hdr)
	}
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body directly — no buffering, no size limit.
	_, _ = io.Copy(w, resp.Body)
}
