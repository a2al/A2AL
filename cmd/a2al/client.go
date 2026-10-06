// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to a2ald REST API (JSON only).
type Client struct {
	Base   string
	Token  string
	HTTP   *http.Client
	Pretty bool // indent JSON for --json
}

func newClient(base, token string, pretty bool) *Client {
	if base == "" {
		base = "http://127.0.0.1:2121"
	}
	base = strings.TrimRight(base, "/")
	return &Client{
		Base:   base,
		Token:  token,
		Pretty: pretty,
		HTTP:   &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *Client) authHeader(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// DoRequest performs HTTP; if out != nil, decodes JSON on 2xx.
func (c *Client) DoRequest(method, path string, body any, out any) (status int, bodyText string, err error) {
	var rdr io.Reader
	jsonBody := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rdr = bytes.NewReader(b)
	} else if jsonBody {
		rdr = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequest(method, c.Base+path, rdr)
	if err != nil {
		return 0, "", err
	}
	c.authHeader(req)
	if jsonBody {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	bodyText = string(raw)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, bodyText, &httpStatusError{code: resp.StatusCode, body: bodyText}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, bodyText, fmt.Errorf("decode json: %w", err)
		}
	}
	return resp.StatusCode, bodyText, nil
}

// PostStream uploads body as raw octets and decodes the JSON reply.
//
// It bypasses the shared client's request timeout: that timeout covers the
// whole exchange, which is right for control-plane calls but would abort a
// large object partway through. Transfer progress is bounded by the connection
// itself, not by a clock started before the first byte.
func (c *Client) PostStream(path string, body io.Reader, out any) error {
	req, err := http.NewRequest(http.MethodPost, c.Base+path, body)
	if err != nil {
		return err
	}
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/octet-stream")

	streamer := &http.Client{Transport: c.HTTP.Transport}
	resp, err := streamer.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{code: resp.StatusCode, body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
	}
	return nil
}

type httpStatusError struct {
	code int
	body string
}

func (e *httpStatusError) Error() string {
	msg := extractAPIError(e.body)
	if msg != "" {
		return fmt.Sprintf("http %d: %s", e.code, msg)
	}
	return fmt.Sprintf("http %d", e.code)
}

func extractAPIError(body string) string {
	var m struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &m) == nil && m.Error != "" {
		return m.Error
	}
	return strings.TrimSpace(body)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "a2al: %v\n", err)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "a2al: "+format+"\n", args...)
	os.Exit(1)
}
