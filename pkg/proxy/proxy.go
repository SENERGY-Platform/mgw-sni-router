/*
 * Copyright (c) 2026 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package proxy forwards TCP connections to a backend chosen by the TLS
// server name or the HTTP Host header. It reads only as far as needed to find
// the name, replays those bytes to the backend and then copies both
// directions unchanged, so TLS is never terminated here.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// maxPeek bounds how much of a connection is buffered while looking for the
// name. A ClientHello and a request header both fit well within it.
const maxPeek = 64 << 10

// Sniffer reads the routing name from the start of a connection.
type Sniffer func(r io.Reader) (string, error)

// Resolver maps a name to a backend; an empty name asks for the default.
type Resolver func(name string) (netip.AddrPort, bool)

type Proxy struct {
	Name        string
	Sniff       Sniffer
	Resolve     Resolver
	PeekTimeout time.Duration
	DialTimeout time.Duration
	Logger      *slog.Logger
}

// Serve accepts until ctx ends or accepting fails for good. On shutdown it
// waits for open connections, which ctx closes; a fatal accept error returns
// at once so the process can exit and be restarted.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	backoff := 5 * time.Millisecond
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			if temporary(err) {
				p.Logger.Warn("accept failed, retrying", "listener", p.Name, "error", err, "backoff", backoff.String())
				time.Sleep(backoff)
				backoff = min(2*backoff, time.Second)
				continue
			}
			return err
		}
		backoff = 5 * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handle(ctx, conn)
		}()
	}
}

// temporary covers timeouts and running out of file descriptors, which pass
// once connections close.
func temporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.ECONNABORTED)
}

func (p *Proxy) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	// Close on shutdown, also while still waiting for the name.
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	log := p.Logger.With("listener", p.Name, "client", conn.RemoteAddr().String())

	_ = conn.SetReadDeadline(time.Now().Add(p.PeekTimeout))
	var peeked bytes.Buffer
	name, err := p.Sniff(io.TeeReader(io.LimitReader(conn, maxPeek), &peeked))
	if err != nil {
		// The sniffer could not find a name, e.g. no SNI extension. The
		// default backend may still take the connection.
		log.Debug("no routing name", "error", err)
		name = ""
	}
	_ = conn.SetReadDeadline(time.Time{})

	backend, ok := p.Resolve(name)
	if !ok {
		log.Warn("no backend for connection", "name", name)
		return
	}
	log = log.With("name", name, "backend", backend.String())

	dialer := net.Dialer{Timeout: p.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", backend.String())
	if err != nil {
		log.Warn("backend unreachable", "error", err)
		return
	}
	defer upstream.Close()
	defer context.AfterFunc(ctx, func() { upstream.Close() })()
	if _, err = upstream.Write(peeked.Bytes()); err != nil {
		log.Warn("replay to backend failed", "error", err)
		return
	}
	log.Debug("forwarding")
	pipe(conn, upstream)
}

// pipe copies both directions until both are done. A clean end of one
// direction is passed on as a half close; an error closes both sides, so the
// other direction does not wait for a peer that is gone.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		cw, ok := dst.(interface{ CloseWrite() error })
		if err != nil || !ok {
			_ = a.Close()
			_ = b.Close()
			return
		}
		_ = cw.CloseWrite()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// SniffTLS returns the server name of a TLS ClientHello. It runs the stdlib
// handshake on a read-only connection and stops it as soon as the hello is
// parsed.
func SniffTLS(r io.Reader) (string, error) {
	var name string
	var seen bool
	err := tls.Server(readOnlyConn{r: r}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name, seen = hello.ServerName, true
			return nil, errHelloRead
		},
	}).Handshake()
	if seen {
		if name == "" {
			return "", errors.New("client hello without server name")
		}
		return name, nil
	}
	return "", err
}

// SniffHTTP returns the host of an HTTP/1.x request header, without port.
func SniffHTTP(r io.Reader) (string, error) {
	req, err := http.ReadRequest(bufio.NewReader(r))
	if err != nil {
		return "", err
	}
	if req.Host == "" {
		return "", errors.New("request without host")
	}
	if host, _, err := net.SplitHostPort(req.Host); err == nil {
		return host, nil
	}
	return req.Host, nil
}

var errHelloRead = errors.New("client hello read")

type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
