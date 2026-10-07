//go:build linux

package diam

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-sctp"
)

// wantDiameterLatencyOptions checks the settings diameterSCTPConfig gives
// an association: SCTP_NODELAY (RFC 6458 §8.1.5) and a delayed-SACK
// frequency of 1 (RFC 6458 §8.1.19).
func wantDiameterLatencyOptions(t *testing.T, side string, c *sctp.Conn) {
	t.Helper()
	noDelay, err := c.NoDelay()
	if err != nil {
		t.Fatalf("%s NoDelay: %v", side, err)
	}
	if !noDelay {
		t.Errorf("%s SCTP_NODELAY is off", side)
	}
	sack, err := c.DelayedSACK()
	if err != nil {
		t.Fatalf("%s DelayedSACK: %v", side, err)
	}
	if sack.Frequency != 1 {
		t.Errorf("%s delayed-SACK frequency = %d, want 1", side, sack.Frequency)
	}
}

// TestSCTPConnsCarryLatencyOptionsWithoutReapplying shows that the dialed
// and the accepted association have the settings from the sctp.Config
// alone: the accepted socket inherits them from the listener, so wrapping
// either does not set them again.
func TestSCTPConnsCarryLatencyOptionsWithoutReapplying(t *testing.T) {
	l, err := MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()
	dialed, err := getMultistreamDialer("sctp", testutil.SCTPTimeout, nil).Dial("sctp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dialed.Close() }()
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(testutil.SCTPTimeout):
		t.Fatal("no association accepted")
	}
	defer func() { _ = server.Close() }()
	wantDiameterLatencyOptions(t, "dialed", dialed.(*SCTPConn).Conn)
	wantDiameterLatencyOptions(t, "accepted", server.(*SCTPConn).Conn)
}

func TestNewSCTPConnAppliesLatencyOptions(t *testing.T) {
	// A plain Config leaves both settings at the kernel defaults.
	addr, err := sctp.ResolveAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&sctp.Config{}).Listen("sctp", addr)
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		if c, err := l.AcceptSCTP(); err == nil {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 1)
			_, _, _ = c.RecvMsg(buf)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
	defer cancel()
	c, err := (&sctp.Config{}).Dial(ctx, "sctp", nil, l.Addr().(*sctp.Addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if noDelay, err := c.NoDelay(); err != nil || noDelay {
		t.Fatalf("kernel default SCTP_NODELAY = %v, %v; the test needs it off", noDelay, err)
	}
	msc, err := NewSCTPConn(c)
	if err != nil {
		t.Fatal(err)
	}
	if msc == nil {
		t.Fatal("NewSCTPConn returned no connection")
	}
	wantDiameterLatencyOptions(t, "wrapped", c)
}

func TestNewSCTPConnReturnsOptionFailure(t *testing.T) {
	if _, err := NewSCTPConn(nil); err == nil {
		t.Fatal("NewSCTPConn(nil) returned no error")
	}
	l, err := MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), testutil.SCTPTimeout)
	defer cancel()
	c, err := diameterSCTPConfig().Dial(ctx, "sctp", nil, l.Addr().(*sctp.Addr))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// SCTP_NODELAY is applied first, so its failure is the one returned.
	msc, err := NewSCTPConn(c)
	if !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "SCTP_NODELAY") {
		t.Fatalf("NewSCTPConn on a closed connection = %v, want the SCTP_NODELAY failure, net.ErrClosed", err)
	}
	if msc != nil {
		t.Fatal("NewSCTPConn returned a connection with its error")
	}
}
