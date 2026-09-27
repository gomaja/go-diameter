package diam_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestServerShutdownActionCanCompleteDPR(t *testing.T) {
	serverSM := sm.New(&sm.Settings{OriginHost: "srv", OriginRealm: "test", VendorID: 13, ProductName: "go-diameter"})
	clientSM := sm.New(&sm.Settings{OriginHost: "cli", OriginRealm: "test", VendorID: 13, ProductName: "go-diameter"})
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
