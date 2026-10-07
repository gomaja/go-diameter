package sm

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

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
	logs := logtest.New()
	cli := &Client{
		Handler: stateMachine,
		Logger:  logs.Logger(),
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for n := 1; ; n++ {
		records, err := logs.Wait(ctx, n)
		if err != nil {
			t.Fatalf("no close failure record: %v", records)
		}
		r := records[n-1]
		if r.Message == "diam: close connection" {
			if err := logError(r); err == nil || err.Error() != "close failed" {
				t.Fatalf("close error missing: %v", r)
			}
			break
		}
	}
}
