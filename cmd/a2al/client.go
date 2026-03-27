// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.Base+path, rdr)
	if err != nil {
		return 0, "", err
	}
	c.authHeader(req)
	if body != nil {
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
