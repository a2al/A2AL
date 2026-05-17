// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// probeHTTPDaemon checks whether an a2ald HTTP API is already reachable at apiURL.
func probeHTTPDaemon(apiURL string) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(apiURL + "/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// proxyMCPStdio forwards newline-delimited JSON-RPC from stdin/stdout to the
// existing daemon's streamable-HTTP MCP endpoint. This lets MCP clients
// configured with --mcp-stdio transparently use an already-running service,
// inheriting its warm DHT state instead of waiting 60–120 s for a cold start.
func proxyMCPStdio(ctx context.Context, mcpURL string) error {
	client := &http.Client{} // no global timeout: SSE responses are long-lived
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB max line
	out := bufio.NewWriter(os.Stdout)
	var sessionID string

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if !in.Scan() {
			return in.Err()
		}
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "POST", mcpURL, bytes.NewReader(line))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("proxy POST: %w", err)
		}

		// Capture session ID from the first response (set during initialize).
		if sessionID == "" {
			if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
				sessionID = sid
			}
		}

		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/event-stream") {
			if err := forwardSSE(resp.Body, out); err != nil && ctx.Err() == nil {
				return fmt.Errorf("proxy SSE: %w", err)
			}
		} else {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("proxy read: %w", err)
			}
			if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 {
				out.Write(trimmed)
				out.WriteByte('\n')
				if err := out.Flush(); err != nil {
					return err
				}
			}
		}
	}
}

// forwardSSE reads an SSE stream and writes each data payload as a JSON line to out.
func forwardSSE(body io.ReadCloser, out *bufio.Writer) error {
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if after, ok := strings.CutPrefix(line, "data: "); ok && after != "" {
			out.WriteString(after)
			out.WriteByte('\n')
			if err := out.Flush(); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
