package diam_test

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm"
)

// lockedBuffer collects log output written by server goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServerShutdownActionCanCompleteDPR(t *testing.T) {
	// A DPR from the shutdown action closes the transport before the server
	// does; closing it again is expected and must not be logged as an error.
	logs := &lockedBuffer{}
	log.SetOutput(logs)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		if out := logs.String(); strings.Contains(out, "use of closed network connection") {
			t.Errorf("shutdown logged closing an already closed connection:\n%s", out)
		}
	})
	serverSM, err := sm.New(&sm.Settings{OriginHost: "srv", OriginRealm: "test", VendorID: 13, ProductName: "go-diameter"})
	if err != nil {
		t.Fatal(err)
	}
	clientSM, err := sm.New(&sm.Settings{OriginHost: "cli", OriginRealm: "test", VendorID: 13, ProductName: "go-diameter"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &diam.Server{Handler: serverSM}
	actions := make(chan error, 1)
	srv.OnShutdownConnection = func(ctx context.Context, c diam.Conn) {
		deadline, ok := ctx.Deadline()
		if !ok {
			actions <- errors.New("shutdown context has no deadline")
			return
		}
		actions <- serverSM.Disconnect(c, sm.DisconnectBusy, time.Until(deadline))
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	defer func() { _ = srv.Close() }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(l) }()
	client := &sm.Client{
		Handler:           clientSM,
		AcctApplicationID: []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))},
	}
	c, err := client.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-actions:
		if err != nil {
			t.Fatalf("DPR during shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown action did not finish")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, diam.ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
}
