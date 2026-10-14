//go:build linux && !386

package dnsdiam

import (
	"context"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
)

// Run socket-backed SCTP tests in Linux Docker, never on the host.
func requireSCTP(t *testing.T) {
	t.Helper()
	listener, err := diam.MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close SCTP listener: %v", err)
	}
}

func TestSCTPDiscoveryManager(t *testing.T) {
	requireSCTP(t)
	listener, err := diam.MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	settings := fixtureSettings("peer.example.net", "example.net")
	machine, err := sm.New(&settings)
	if err != nil {
		t.Fatal(err)
	}
	server := &diam.Server{Network: "sctp", Handler: machine, Dict: fixtureDictionary()}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SCTP server did not stop")
		}
	})
	addr := listener.Addr().String()
	t.Logf("synthetic SCTP Diameter %s", addr)
	d := liveDiscovery(t, addr, SCTP)
	manager, err := peer.New(peer.Config{Settings: fixtureSettings("client.example.net", "local.net"), Timers: peer.Timers{Closing: 50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	controller, err := NewController(d, manager, Policy{AllowPlaintext: true, Authorize: authorizeFixture})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := controller.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = controller.Ensure(ctx, "example.net", 4); err != nil {
		t.Fatal(err)
	}
	if !manager.HasRoute("example.net", 4) {
		t.Fatal("SCTP discovered route missing")
	}
	if err = controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.HasRoute("example.net", 4) {
		t.Fatal("released SCTP route remained eligible")
	}
}
