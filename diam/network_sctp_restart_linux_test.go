//go:build linux && !386

package diam

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

func requireSCTP(t *testing.T) {
	t.Helper()
	listener, err := MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close SCTP listener: %v", err)
	}
}

func TestSCTPRestartSubscriptionInheritance(t *testing.T) {
	requireSCTP(t)
	for _, multi := range []bool{false, true} {
		name := "raw"
		if multi {
			name = "multistream"
		}
		t.Run(name, func(t *testing.T) {
			var listener net.Listener
			var err error
			if multi {
				listener, err = MultistreamListen("sctp4", "127.0.0.1:0")
			} else {
				listener, err = Listen("sctp4", "127.0.0.1:0")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			accepted := make(chan net.Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- c
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			dialed, err := sctpDialer{}.DialContext(ctx, "sctp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dialed.Close() }()
			var conn net.Conn
			select {
			case conn = <-accepted:
			case err = <-acceptErr:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer func() { _ = conn.Close() }()
			var raw *sctp.Conn
			if multi {
				adapter := conn.(*SCTPConn)
				if !adapter.restartAware {
					t.Fatal("accepted adapter hides restart")
				}
				raw = adapter.Conn
			} else {
				raw = conn.(*sctp.Conn)
			}
			if subscribed, err := raw.Subscribed(sctp.EventAssocChange); err != nil || !subscribed {
				t.Fatalf("accepted subscription=%v,%v", subscribed, err)
			}
			d := dialed.(*SCTPConn)
			if subscribed, err := d.Subscribed(sctp.EventAssocChange); err != nil || subscribed || d.restartAware {
				t.Fatalf("dialed subscription=%v,%v restart-aware=%v", subscribed, err, d.restartAware)
			}
		})
	}
}

func TestNewSCTPConnSubscribesRestart(t *testing.T) {
	requireSCTP(t)
	addr, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&sctp.Config{}).Listen("sctp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan *sctp.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := listener.AcceptSCTP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	raw, err := (&sctp.Config{}).Dial(ctx, "sctp4", nil, listener.Addr().(*sctp.Addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	select {
	case peer := <-accepted:
		defer func() { _ = peer.Close() }()
	case err = <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if subscribed, err := raw.Subscribed(sctp.EventAssocChange); err != nil || subscribed {
		t.Fatalf("plain socket subscription=%v,%v", subscribed, err)
	}
	wrapped, err := NewSCTPConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	if subscribed, err := raw.Subscribed(sctp.EventAssocChange); err != nil || !subscribed || !wrapped.(*SCTPConn).restartAware {
		t.Fatalf("wrapped subscription=%v,%v", subscribed, err)
	}
}
