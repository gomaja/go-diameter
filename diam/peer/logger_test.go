package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/sm"
)

type lockedRecords struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedRecords) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedRecords) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Split(strings.TrimSpace(b.buf.String()), "\n")
}

// closeFailConn fails every Close after closing the pipe it wraps.
type closeFailConn struct{ net.Conn }

func (c closeFailConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("close failed")
}

// TestManagerDialedConnectionsUseConfigLogger checks that the diam.Server
// the Manager builds for an outbound connection logs to Config.Logger.
func TestManagerDialedConnectionsUseConfigLogger(t *testing.T) {
	records := &lockedRecords{}
	var remote net.Conn
	m, err := New(Config{
		Settings: testSettings("local.example.net"),
		Logger:   slog.New(slog.NewJSONHandler(records, &slog.HandlerOptions{Level: slog.LevelDebug})),
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
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(strings.Join(records.lines(), "\n"), `"msg":"diam: close connection","network":"pipe"`) {
		if time.Now().After(deadline) {
			t.Fatalf("Config.Logger received no close failure; records: %v", records.lines())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestManagerLogsOnPeerEventPanic(t *testing.T) {
	records := &lockedRecords{}
	delivered := make(chan struct{}, 2)
	m, err := New(Config{
		Settings: testSettings("local.example.net"),
		Logger:   slog.New(slog.NewJSONHandler(records, nil)),
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

	var rec map[string]any
	deadline := time.Now().Add(2 * time.Second)
	for rec == nil {
		for _, line := range records.lines() {
			var r map[string]any
			if json.Unmarshal([]byte(line), &r) == nil && r["msg"] == "peer: panic in OnPeerEvent" {
				rec = r
			}
		}
		if rec == nil && time.Now().After(deadline) {
			t.Fatalf("no panic record; records: %v", records.lines())
		}
		time.Sleep(time.Millisecond)
	}
	if rec["level"] != "ERROR" || rec["panic"] != "observer boom" || rec["peer_host"] != "faulty.example.net" {
		t.Errorf("panic record = %v", rec)
	}
	if stack, _ := rec["stack"].(string); !strings.Contains(stack, "TestManagerLogsOnPeerEventPanic") {
		t.Errorf("stack does not show the panicking observer:\n%s", stack)
	}
}
