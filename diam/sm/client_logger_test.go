package sm

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// closeFailConn fails every Close after closing the pipe it wraps.
type closeFailConn struct{ net.Conn }

func (c closeFailConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("close failed")
}

// TestClientConnectionsUseClientLogger checks that the connections a Client
// opens log to Client.Logger.
func TestClientConnectionsUseClientLogger(t *testing.T) {
	stateMachine, err := New(&Settings{OriginHost: "cli", OriginRealm: "example.net", VendorID: 13, ProductName: "go-diameter"})
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedLog{}
	cli := &Client{
		Handler: stateMachine,
		Logger:  slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	local, remote := net.Pipe()
	// The peer reads the CER and goes away, which fails the handshake and
	// ends the connection; closing it then fails.
	go func() {
		_, _ = io.ReadAtLeast(remote, make([]byte, 20), 20)
		_ = remote.Close()
	}()
	if _, err := cli.NewConn(closeFailConn{local}, "peer.example.net:3868"); err == nil {
		t.Fatal("handshake with a peer that went away succeeded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), `msg="diam: close connection"`) {
		if time.Now().After(deadline) {
			t.Fatalf("Client.Logger received no close failure; log:\n%s", logs.String())
		}
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(logs.String(), "error=\"close failed\"") {
		t.Errorf("record lacks the close error:\n%s", logs.String())
	}
}
