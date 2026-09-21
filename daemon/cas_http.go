// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

// acceptCAS handles a stream whose a2cs magic has already been consumed.
// Admission and ACL match a2s1; the remainder is HTTP/1.1 answered by the
// daemon (never bridged to service_tcp).
func (d *Daemon) acceptCAS(ac *host.AgentConn, str quic.Stream) {
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	d.handleCASStream(ac.Local, ac.Remote, ac.RemoteAddr(), str)
	_ = str.Close()
}

func (d *Daemon) handleCASStream(local, remote a2al.Address, src net.Addr, rw io.ReadWriter) {
	token, aerr := host.ReadServiceAdmission(rw)
	if aerr != nil {
		d.log.Debug("gateway: a2cs admission read", "err", aerr)
		return
	}
	allowed := d.decideAccess(local, remote, token, src, accessCAS)
	reason := ""
	if !allowed {
		reason = "denied"
	}
	if werr := host.WriteAccessResult(rw, allowed, reason); werr != nil {
		return
	}
	if !allowed {
		d.log.Warn("gateway: cas access denied", "local_aid", local.String(), "remote_aid", remote.String())
		return
	}
	if s, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = s.SetDeadline(time.Time{})
	}
	d.serveCASHTTP(rw, local)
}

func (d *Daemon) serveCASHTTP(rw io.ReadWriter, aid a2al.Address) {
	req, err := http.ReadRequest(bufio.NewReader(rw))
	if err != nil {
		return
	}
	defer req.Body.Close()
	id, ok := group.ParseCASPath(req.URL.Path)
	out := &streamResponseWriter{w: rw}
	if !ok {
		http.Error(out, "not found", http.StatusNotFound)
		return
	}
	d.serveCASFile(out, aid, id, req.Method)
}

type streamResponseWriter struct {
	w           io.Writer
	hdr         http.Header
	wroteHeader bool
}

func (s *streamResponseWriter) Header() http.Header {
	if s.hdr == nil {
		s.hdr = make(http.Header)
	}
	return s.hdr
}

func (s *streamResponseWriter) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.w.Write(p)
}

func (s *streamResponseWriter) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	if s.hdr != nil {
		_ = s.hdr.Write(&b)
	}
	b.WriteString("Connection: close\r\n\r\n")
	_, _ = s.w.Write([]byte(b.String()))
}

func (d *Daemon) fetchCASToFile(ctx context.Context, local, remote a2al.Address, id [32]byte, dest, token string) error {
	stream, err := d.dialCAS(ctx, local, remote, token)
	if err != nil {
		return err
	}
	defer stream.Close()

	req, err := http.NewRequest(http.MethodGet, "http://cas"+group.CASPath(id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Connection", "close")
	if err := req.Write(stream); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 32*1024), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cas: remote status %d", resp.StatusCode)
	}
	return writeCASFile(resp.Body, dest, id)
}
