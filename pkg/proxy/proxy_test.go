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

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// backend is a test server that answers with its own name, so a test sees
// which backend a connection reached.
func backend(t *testing.T, name string, useTLS bool) netip.AddrPort {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, name+" "+r.Host)
	}))
	if useTLS {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

func startProxy(t *testing.T, sniff Sniffer, routes map[string]netip.AddrPort) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		Name:  "test",
		Sniff: sniff,
		Resolve: func(name string) (netip.AddrPort, bool) {
			ap, ok := routes[name]
			if !ok {
				ap, ok = routes["*"]
			}
			return ap, ok
		},
		PeekTimeout: 2 * time.Second,
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.DiscardHandler),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

func get(t *testing.T, client *http.Client, url string) (string, error) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestTLSRouting(t *testing.T) {
	a := backend(t, "a", true)
	b := backend(t, "b", true)
	addr := startProxy(t, SniffTLS, map[string]netip.AddrPort{"a.example": a, "b.example": b, "*": b})

	client := func(serverName string) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: serverName, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
	}
	for sni, want := range map[string]string{"a.example": "a", "b.example": "b", "": "b"} {
		body, err := get(t, client(sni), "https://"+addr+"/")
		if err != nil {
			t.Fatalf("sni %q: %v", sni, err)
		}
		if !strings.HasPrefix(body, want+" ") {
			t.Errorf("sni %q reached %q, want %q", sni, body, want)
		}
	}
}

func TestTLS10ClientHello(t *testing.T) {
	// Old device firmware may still offer only TLS 1.0. The router must read
	// the name regardless; whether the handshake succeeds is up to the backend.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		_ = tls.Client(clientConn, &tls.Config{ServerName: "syrconnect.de", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, InsecureSkipVerify: true}).Handshake()
	}()
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	name, err := SniffTLS(serverConn)
	serverConn.Close()
	if err != nil || name != "syrconnect.de" {
		t.Fatalf("SniffTLS = %q, %v", name, err)
	}
}

func TestHTTPRouting(t *testing.T) {
	a := backend(t, "a", false)
	b := backend(t, "b", false)
	addr := startProxy(t, SniffHTTP, map[string]netip.AddrPort{"a.example": a, "b.example": b})

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	for host, want := range map[string]string{"a.example": "a a.example", "b.example:80": "b b.example:80"} {
		body, err := get(t, client, "http://"+host+"/WebServices/x.asmx")
		if err != nil {
			t.Fatalf("host %q: %v", host, err)
		}
		if body != want {
			t.Errorf("host %q reached %q, want %q", host, body, want)
		}
	}
	// No default backend: an unknown host is dropped.
	if _, err := get(t, client, "http://c.example/"); err == nil {
		t.Error("unknown host without default was forwarded")
	}
}

func TestHTTPRequestBodyIsReplayed(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the whole body before answering; net/http is not full duplex.
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	defer echo.Close()
	addr := startProxy(t, SniffHTTP, map[string]netip.AddrPort{"*": netip.MustParseAddrPort(echo.Listener.Addr().String())})

	payload := "xml=" + strings.Repeat("<sc/>", 20000) // larger than one read
	resp, err := http.Post("http://"+addr+"/", "application/x-www-form-urlencoded", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != payload {
		t.Errorf("body changed in transit: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestShutdownDuringPeek(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		Name:        "test",
		Sniff:       SniffTLS,
		Resolve:     func(string) (netip.AddrPort, bool) { return netip.AddrPort{}, false },
		PeekTimeout: time.Minute,
		DialTimeout: time.Second,
		Logger:      slog.New(slog.DiscardHandler),
	}
	done := make(chan error)
	go func() { done <- p.Serve(ctx, ln) }()

	// A client that connects and sends nothing.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown waited for the peek timeout")
	}
}

func TestClientWithoutSNIGoesToDefault(t *testing.T) {
	// SNI-less and unparsable hellos both fall back to the default backend.
	def := backend(t, "default", true)
	addr := startProxy(t, SniffTLS, map[string]netip.AddrPort{"*": def})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// SSLv2-compatible ClientHello header, which crypto/tls rejects.
	if _, err = c.Write([]byte{0x80, 0x2e, 0x01, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	// The default backend (a TLS server) answers the garbage with an alert
	// or closes; either way the connection was forwarded rather than held.
	buf := make([]byte, 16)
	if _, err = c.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("connection not forwarded to the default backend")
		}
	}
}
