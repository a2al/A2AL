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
	allowed := d.casAdmitStream(local, remote, token, src)
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
	d.serveCASHTTPAuth(rw, local, remote, token, src)
}

func (d *Daemon) casAdmitStream(local, remote a2al.Address, token string, src net.Addr) bool {
	if local == d.nodeAddr {
		return d.decideNodeAdminAccess(remote, token, src)
	}
	d.regMu.RLock()
	e := d.reg.Get(local)
	d.regMu.RUnlock()
	if e == nil {
		return true
	}
	if d.aclIP.locked(src) {
		return false
	}
	if aclDenies(e.ACL, remote) {
		d.aclIP.noteFail(src)
		return false
	}
	if e.ACL.Allows(remote, token) {
		d.aclIP.noteOK(src)
		if usedJoinPassword(e.ACL, remote, token) {
			d.recordJoinAID(local, remote)
		}
		return true
	}
	if token != "" {
		return true
	}
	d.aclIP.noteFail(src)
	return false
}

func (d *Daemon) casObjectAllowed(local, remote a2al.Address, token string, src net.Addr, id [32]byte) bool {
	if local == d.nodeAddr {
		return d.decideNodeAdminAccess(remote, token, src)
	}
	d.regMu.RLock()
	e := d.reg.Get(local)
	d.regMu.RUnlock()
	if e == nil {
		return true
	}
	if d.aclIP.locked(src) {
		return false
	}
	if aclDenies(e.ACL, remote) {
		return false
	}
	if e.ACL.Allows(remote, token) {
		return true
	}
	rec, ok := d.casRec(local, id)
	return ok && grantMatch(rec.Grant, token)
}

func (d *Daemon) serveCASHTTP(rw io.ReadWriter, aid a2al.Address) {
	d.serveCASHTTPAuth(rw, aid, a2al.Address{}, "", nil)
}

func (d *Daemon) serveCASHTTPAuth(rw io.ReadWriter, aid, remote a2al.Address, token string, src net.Addr) {
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
	if !d.casObjectAllowed(aid, remote, token, src, id) {
		http.Error(out, "forbidden", http.StatusForbidden)
		return
	}
	if d.serveCASFile(out, aid, id, req.Method) && (req.Method == http.MethodGet || req.Method == "") {
		d.noteCASServed(aid, remote, id)
	}
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
	return copyCASHTTP(stream, id, dest)
}

func (d *Daemon) fetchCASToFileLive(ctx context.Context, local, remote a2al.Address, id [32]byte, dest, token string) error {
	if d.connPool == nil {
		return errCASNoLive
	}
	conn := d.connPool.getLive(local, remote)
	if conn == nil {
		return errCASNoLive
	}
	stream, err := host.AdmitCASStream(ctx, conn, token)
	if err != nil {
		return err
	}
	defer stream.Close()
	return copyCASHTTP(stream, id, dest)
}

func copyCASHTTP(stream io.ReadWriter, id [32]byte, dest string) error {
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
