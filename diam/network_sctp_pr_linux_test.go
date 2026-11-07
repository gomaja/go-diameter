//go:build linux

package diam

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-sctp"
)

func requirePRSCTPDefault(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/sctp/prsctp_enable")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("net.sctp.prsctp_enable = %q; need 1 to detect an unset PartialReliability", strings.TrimSpace(string(b)))
	}
}

func wantPRSCTP(t *testing.T, local, peer *sctp.Conn, offer, peerOffer bool) {
	t.Helper()
	want := offer && peerOffer
	localResult, err := local.PRSupported()
	if err != nil || localResult != want {
		t.Errorf("go-diameter PRSupported = %v, %v; want %v (offer=%v peer=%v)", localResult, err, want, offer, peerOffer)
	}
	peerResult, err := peer.PRSupported()
	if err != nil || peerResult != want {
		t.Errorf("raw peer PRSupported = %v, %v; want %v (offer=%v peer=%v)", peerResult, err, want, offer, peerOffer)
	}
	t.Logf("PR-SCTP association local=%s remote=%s go_offer=%t peer_offer=%t supported=%t peer_supported=%t", local.LocalAddr(), local.RemoteAddr(), offer, peerOffer, localResult, peerResult)
}

func rawPRSCTPConn(c net.Conn) *sctp.Conn {
	if secured, ok := c.(*tls.Conn); ok {
		c = secured.NetConn()
	}
	if adapter, ok := c.(*SCTPConn); ok {
		return adapter.Conn
	}
	return c.(*sctp.Conn)
}

func startPRSCTPServer(t *testing.T, srv *Server, serve func() error) (net.Addr, <-chan Conn) {
	t.Helper()
	accepted := make(chan Conn, 1)
	srv.OnNewConnection = func(c Conn) { accepted <- c }
	finished := make(chan error, 1)
	go func() { finished <- serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-finished:
			if !errors.Is(err, ErrServerClosed) {
				t.Errorf("ListenAndServe: %v", err)
			}
		case <-time.After(testutil.SCTPTimeout):
			t.Error("ListenAndServe did not terminate")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
	defer cancel()
	for {
		srv.mu.Lock()
		for l := range srv.listeners {
			addr := l.Addr()
			srv.mu.Unlock()
			return addr, accepted
		}
		srv.mu.Unlock()
		select {
		case err := <-finished:
			finished <- err
			t.Fatalf("ListenAndServe: %v", err)
		case <-ctx.Done():
			t.Fatal("listener did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

// Missing explicit socket defaults must fail even when the kernel offers PR-SCTP.
func TestSCTPPartialReliabilityListeners(t *testing.T) {
	requirePRSCTPDefault(t)
	for _, tc := range []struct {
		kind  string
		offer bool
	}{{"Server", false}, {"Server", true}, {"MultistreamListen", false}, {"Listen", false}} {
		kind, offer := tc.kind, tc.offer
		for _, peerOffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/offer=%t/peer=%t", kind, offer, peerOffer), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
				defer cancel()
				var addr net.Addr
				var accepted <-chan Conn
				var listener net.Listener
				var err error
				if kind == "Server" {
					srv := &Server{Network: "sctp4", Addr: "127.0.0.1:0", SCTPPartialReliability: offer}
					addr, accepted = startPRSCTPServer(t, srv, srv.ListenAndServe)
				} else {
					if kind == "Listen" {
						listener, err = Listen("sctp4", "127.0.0.1:0")
					} else {
						listener, err = MultistreamListen("sctp4", "127.0.0.1:0")
					}
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = listener.Close() }()
					addr = listener.Addr()
				}
				ra, err := sctp.ResolveAddr("sctp4", addr.String())
				if err != nil {
					t.Fatal(err)
				}
				peer, err := (&sctp.Config{PartialReliability: &peerOffer}).Dial(ctx, "sctp4", nil, ra)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				var local net.Conn
				if listener != nil {
					local, err = listener.Accept()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					select {
					case c := <-accepted:
						defer c.Close()
						local = c.Connection()
					case <-ctx.Done():
						t.Fatal("association was not accepted")
					}
				}
				defer func() { _ = local.Close() }()
				wantPRSCTP(t, rawPRSCTPConn(local), peer, offer, peerOffer)
			})
		}
	}
}

func TestSCTPPartialReliabilityDialers(t *testing.T) {
	requirePRSCTPDefault(t)
	for _, tc := range []struct {
		kind  string
		offer bool
	}{{"Server", false}, {"Server", true}, {"DialNetwork", false}} {
		kind, offer := tc.kind, tc.offer
		for _, peerOffer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/offer=%t/peer=%t", kind, offer, peerOffer), func(t *testing.T) {
				ra, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listener, err := (&sctp.Config{PartialReliability: &peerOffer}).Listen("sctp4", ra)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
				defer cancel()
				var c Conn
				if kind == "Server" {
					srv := &Server{Network: "sctp4", Addr: listener.Addr().String(), SCTPPartialReliability: offer}
					c, err = srv.DialContext(ctx)
				} else {
					c, err = DialNetwork("sctp4", listener.Addr().String(), nil, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				peer, err := listener.AcceptSCTP()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				wantPRSCTP(t, rawPRSCTPConn(c.Connection()), peer, offer, peerOffer)
			})
		}
	}
}
