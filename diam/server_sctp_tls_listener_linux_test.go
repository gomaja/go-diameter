//go:build linux && !386

package diam

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

func TestBuiltInSCTPTLSListenerUsesRestartAdapter(t *testing.T) {
	requireSCTP(t)
	cert := generationCertificate(t)
	accepted := make(chan Conn, 1)
	srv := &Server{Network: "sctp4", Addr: "127.0.0.1:0",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }},
		OnNewConnection: func(c Conn) { accepted <- c },
	}
	var serveErr error
	finished := make(chan struct{})
	go func() { serveErr = srv.ListenAndServeTLS("", ""); close(finished) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-finished:
			if serveErr != nil && !errors.Is(serveErr, ErrServerClosed) {
				t.Errorf("serve: %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("TLS listener did not terminate")
		}
	})
	var addr net.Addr
	deadline := time.Now().Add(3 * time.Second)
	for addr == nil && time.Now().Before(deadline) {
		srv.mu.Lock()
		for listener := range srv.listeners {
			addr = listener.Addr()
		}
		srv.mu.Unlock()
		if addr == nil {
			select {
			case <-finished:
				t.Fatalf("listen: %v", serveErr)
			case <-time.After(time.Millisecond):
			}
		}
	}
	if addr == nil {
		t.Fatal("built-in TLS listener did not start")
	}
	ra, err := sctp.ResolveAddr("sctp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := (&sctp.Config{}).Dial(ctx, "sctp4", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- synthetic local certificate
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		tlsConn, ok := c.Connection().(*tls.Conn)
		if !ok {
			t.Fatalf("built-in TLS connection is %T", c.Connection())
		}
		adapter, ok := tlsConn.NetConn().(*SCTPConn)
		if !ok || !adapter.restartAware {
			t.Fatalf("underlying TLS transport is %T; want restart-aware SCTP adapter", tlsConn.NetConn())
		}
	case <-ctx.Done():
		t.Fatal("TLS handshake did not publish the accepted connection")
	}
}
