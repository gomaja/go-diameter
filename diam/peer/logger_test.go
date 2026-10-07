package peer

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm"
)

// closeFailConn fails every Close after closing the pipe it wraps.
type closeFailConn struct{ net.Conn }

func (c closeFailConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("close failed")
}

// TestManagerDialedConnectionsUseConfigLogger checks that the diam.Server
// the Manager builds for an outbound connection logs to Config.Logger.
func TestManagerDialedConnectionsUseConfigLogger(t *testing.T) {
	records := logtest.New()
	var remote net.Conn
	m, err := New(Config{
		Settings: testSettings("local.example.net"),
		Logger:   records.Logger(),
		Dial: func(context.Context, Endpoint) (net.Conn, error) {
			local, peer := net.Pipe()
			remote = peer
			return closeFailConn{local}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A closed Manager admits no session, so dialEndpoint closes the
	// connection it opened, and that Close fails.
	if err := m.Close(context.Background(), sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.dialEndpoint(ctx, Endpoint{Network: "tcp", Address: "peer.example.net:3868"}, nil, 1); err == nil {
		t.Fatal("dial after Close succeeded")
	}
	if remote != nil {
		defer func() { _ = remote.Close() }()
	}
	got, err := records.Wait(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Message != "diam: close connection" || logtest.Attr(got[0], "network").String() != "pipe" {
		t.Fatalf("Config.Logger records: %v", got)
	}
}

func TestManagerLogsOnPeerEventPanic(t *testing.T) {
	records := logtest.New()
	delivered := make(chan struct{}, 2)
	m, err := New(Config{
		Settings: testSettings("local.example.net"),
		Logger:   records.Logger(),
		OnPeerEvent: func(e PeerEvent) {
			delivered <- struct{}{}
			if e.Peer.Host == "faulty.example.net" {
				panic("observer boom")
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeManager(t, m, nil) })

	m.notify(PeerEvent{Peer: PeerSnapshot{Host: "faulty.example.net"}})
	m.notify(PeerEvent{Peer: PeerSnapshot{Host: "next.example.net"}})
	for range 2 {
		select {
		case <-delivered:
		case <-time.After(2 * time.Second):
			t.Fatal("a panic in OnPeerEvent stopped event delivery")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := records.Wait(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	rec := got[0]
	if rec.Level != slog.LevelError || rec.Message != "peer: panic in OnPeerEvent" || logtest.Attr(rec, "panic").Any() != "observer boom" || logtest.Attr(rec, "peer_host").String() != "faulty.example.net" {
		t.Errorf("panic record = %v", rec)
	}
	if stack := logtest.Attr(rec, "stack").String(); !strings.Contains(stack, "TestManagerLogsOnPeerEventPanic") {
		t.Errorf("stack does not show the panicking observer:\n%s", stack)
	}
}
