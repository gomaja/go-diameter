package diam_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type handshakeObservedListener struct {
	net.Listener
	started chan struct{}
}

func (l *handshakeObservedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &handshakeObservedConn{Conn: c, started: l.started}, nil
}

type handshakeObservedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *handshakeObservedConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func expectTLSClientClosed(t *testing.T, client net.Conn, within time.Duration) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err := client.Read(b[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("stalled TLS handshake read = %v, want EOF", err)
	}
}

func tlsHandshakeTestServer(t *testing.T, srv *diam.Server) (string, string, <-chan error, <-chan struct{}) {
	t.Helper()
	certFile, _, cert := newTestCertificateFiles(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	tlsLn := tls.NewListener(&handshakeObservedListener{Listener: ln, started: started},
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close(); _ = tlsLn.Close() })
	return ln.Addr().String(), certFile, done, started
}

func TestServerTLSHandshakeHonorsReadTimeout(t *testing.T) {
	srv := &diam.Server{ReadTimeout: 80 * time.Millisecond}
	addr, _, _, _ := tlsHandshakeTestServer(t, srv)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	start := time.Now()
	if err := client.SetReadDeadline(start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err = client.Read(b[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("stalled TLS handshake read = %v, want EOF", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("stalled TLS handshake closed after %v, want within 500ms", elapsed)
	}
}

func TestServerTLSHandshakeDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		handshake, read, write time.Duration
		partial                bool
	}{
		{name: "configured", handshake: 80 * time.Millisecond},
		{name: "partial ClientHello", handshake: 80 * time.Millisecond, partial: true},
		{name: "read minimum", handshake: 300 * time.Millisecond, read: 80 * time.Millisecond},
		{name: "write minimum", handshake: 300 * time.Millisecond, write: 80 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &diam.Server{TLSHandshakeTimeout: tc.handshake, ReadTimeout: tc.read, WriteTimeout: tc.write}
			addr, _, _, _ := tlsHandshakeTestServer(t, srv)
			client, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if tc.partial {
				if _, err := client.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x40}); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			expectTLSClientClosed(t, client, time.Second)
			if elapsed := time.Since(start); elapsed > 220*time.Millisecond {
				t.Fatalf("handshake closed after %v, want within 220ms", elapsed)
			}
		})
	}
}

func TestServerTLSHandshakeNegativeDisablesDeadline(t *testing.T) {
	srv := &diam.Server{TLSHandshakeTimeout: -1, ReadTimeout: 80 * time.Millisecond}
	addr, _, _, _ := tlsHandshakeTestServer(t, srv)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err = client.Read(b[:])
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("negative timeout read = %v, want client deadline", err)
	}
}

func TestServerTLSHandshakeClearsDeadline(t *testing.T) {
	opened := make(chan struct{}, 1)
	srv := &diam.Server{TLSHandshakeTimeout: 80 * time.Millisecond, ReadTimeout: 350 * time.Millisecond,
		OnNewConnection: func(diam.Conn) { opened <- struct{}{} }}
	addr, certFile, _, _ := tlsHandshakeTestServer(t, srv)
	client, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
		testClientTLSConfig(t, certFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case <-opened:
	case <-time.After(time.Second):
		t.Fatal("OnNewConnection not called after TLS handshake")
	}
	start := time.Now()
	if err := client.SetReadDeadline(start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, err = client.Read(b[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("post-handshake read = %v, want EOF", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 800*time.Millisecond {
		t.Fatalf("post-handshake ReadTimeout elapsed %v, want approximately 350ms", elapsed)
	}
}

func TestServerCloseDuringTLSHandshake(t *testing.T) {
	srv := &diam.Server{TLSHandshakeTimeout: -1}
	addr, _, serveDone, started := tlsHandshakeTestServer(t, srv)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake did not start")
	}
	start := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Close took %v", elapsed)
	}
	expectTLSClientClosed(t, client, time.Second)
	select {
	case err := <-serveDone:
		if !errors.Is(err, diam.ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestServerShutdownDuringTLSHandshake(t *testing.T) {
	srv := &diam.Server{TLSHandshakeTimeout: -1}
	addr, _, _, started := tlsHandshakeTestServer(t, srv)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	expectTLSClientClosed(t, client, time.Second)
}
