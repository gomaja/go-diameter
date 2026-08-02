// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// These tests use dictionary, settings and functions from sm_test.go.

// newLivenessClient returns a watchdog-enabled client for the acct
// application the shared test dictionary declares.
func newLivenessClient() *Client {
	return &Client{
		Dict:               dict.Default,
		Handler:            New(clientSettings),
		MaxRetransmits:     0,
		RetransmitInterval: 50 * time.Millisecond,
		EnableWatchdog:     true,
		WatchdogInterval:   50 * time.Millisecond,
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001)),
		},
	}
}

// TestCleanEOFWakesSupervisor covers the supervisor pattern an sm.Client user
// writes: block on ErrorReports and CloseNotify, and reconnect when either
// fires. A peer that completes the handshake and then closes cleanly before
// sending anything else must wake one of them. EOF is deliberately not
// reported as an error, so the wake-up has to come from CloseNotify.
func TestCleanEOFWakesSupervisor(t *testing.T) {
	handshake := make(chan diam.Conn, 8)
	ssm := New(serverSettings)
	ssm.mux.HandleFunc("ALL", func(diam.Conn, *diam.Message) {})
	go func() {
		for c := range ssm.HandshakeNotify() {
			handshake <- c
		}
	}()

	srv := diamtest.NewServer(ssm, dict.Default)
	defer srv.Close()

	cli := newLivenessClient()
	conn, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var peer diam.Conn
	select {
	case peer = <-handshake:
	case <-time.After(5 * time.Second):
		t.Fatal("no server-side handshake")
	}

	// Peer closes cleanly, before any further message is exchanged.
	peer.Close()

	notifier, ok := conn.(diam.CloseNotifier)
	if !ok {
		t.Fatal("conn does not implement diam.CloseNotifier")
	}

	select {
	case <-cli.Handler.ErrorReports():
	case <-notifier.CloseNotify():
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor stalled: neither ErrorReports nor CloseNotify fired on clean peer FIN")
	}
}

// TestCloseNotifyAfterPeerGone covers the same failure from the other side of
// the race: a CloseNotify registration that lands after the connection is
// already gone must still fire. The sleep lets the read loop finish before
// the first registration, which is what the watchdog goroutine risks doing
// when it is scheduled late.
func TestCloseNotifyAfterPeerGone(t *testing.T) {
	handshake := make(chan diam.Conn, 8)
	ssm := New(serverSettings)
	ssm.mux.HandleFunc("ALL", func(diam.Conn, *diam.Message) {})
	go func() {
		for c := range ssm.HandshakeNotify() {
			handshake <- c
		}
	}()

	srv := diamtest.NewServer(ssm, dict.Default)
	defer srv.Close()

	// Watchdog disabled so nothing registers CloseNotify before we do.
	cli := newLivenessClient()
	cli.EnableWatchdog = false

	conn, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case peer := <-handshake:
		peer.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no server-side handshake")
	}

	// Let the client's read loop observe the FIN and run its exit path
	// before anything registers for notification.
	time.Sleep(200 * time.Millisecond)

	select {
	case <-conn.(diam.CloseNotifier).CloseNotify():
	case <-time.After(5 * time.Second):
		t.Fatal("CloseNotify registered after the peer was gone never fired")
	}
}

// errWriteConn is a diam.Conn whose writes always fail and whose read side
// stays silent, standing in for a transport that accepted the handshake and
// then broke in the send direction only. A real conn is unsuitable here:
// breaking its socket also trips the read loop, which reports and notifies on
// its own and would mask what dwr did.
type errWriteConn struct {
	mu       sync.Mutex
	writes   int
	closed   bool
	closec   chan struct{}
	writeErr error
}

func newErrWriteConn() *errWriteConn {
	return &errWriteConn{closec: make(chan struct{}), writeErr: errors.New("broken pipe")}
}

func (c *errWriteConn) Write(b []byte) (int, error) {
	return c.WriteStream(b, 0)
}

func (c *errWriteConn) WriteStream([]byte, uint) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return 0, c.writeErr
}

func (c *errWriteConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closec)
	}
}

func (c *errWriteConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *errWriteConn) CloseNotify() <-chan struct{} { return c.closec }
func (c *errWriteConn) LocalAddr() net.Addr          { return nil }
func (c *errWriteConn) RemoteAddr() net.Addr         { return nil }
func (c *errWriteConn) TLS() *tls.ConnectionState    { return nil }
func (c *errWriteConn) Dictionary() *dict.Parser     { return dict.Default }
func (c *errWriteConn) Context() context.Context     { return context.Background() }
func (c *errWriteConn) SetContext(context.Context)   {}
func (c *errWriteConn) Connection() net.Conn         { return nil }

// TestWatchdogReportsWriteError verifies that a DWR which cannot be written
// disconnects and reports, instead of returning silently and leaving the
// outer watchdog loop to retry the failed send on every interval forever.
func TestWatchdogReportsWriteError(t *testing.T) {
	cli := newLivenessClient()
	c := newErrWriteConn()

	cli.dwr(c, 0, make(chan struct{}))

	select {
	case er := <-cli.Handler.ErrorReports():
		if er.Error == nil {
			t.Fatal("error report carries no error")
		}
	default:
		t.Fatal("watchdog write failure was not reported")
	}

	select {
	case <-c.CloseNotify():
	default:
		t.Fatal("watchdog write failure did not close the connection")
	}
}

// TestWatchdogWriteErrorStopsRetrying verifies the watchdog loop terminates
// on a write error rather than spinning failed sends indefinitely. Without a
// disconnect, watchdog re-arms its interval timer and tries again forever.
func TestWatchdogWriteErrorStopsRetrying(t *testing.T) {
	cli := newLivenessClient()
	c := newErrWriteConn()

	done := make(chan struct{})
	go func() {
		cli.watchdog(c, make(chan struct{}))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog kept spinning after a write failure")
	}

	// One DWR attempt per configured transmit, then it gives up.
	if n, want := c.writeCount(), int(cli.MaxRetransmits)+1; n != want {
		t.Fatalf("watchdog wrote %d DWRs, want %d", n, want)
	}
}

// TestClientTimeoutsArePlumbed verifies sm.Client's ReadTimeout and
// WriteTimeout reach the connection, so a client can bound its I/O the way a
// raw diam.Server dialer already can.
func TestClientTimeoutsArePlumbed(t *testing.T) {
	ssm := New(serverSettings)
	ssm.mux.HandleFunc("ALL", func(diam.Conn, *diam.Message) {})
	srv := diamtest.NewServer(ssm, dict.Default)
	defer srv.Close()

	cli := newLivenessClient()
	cli.EnableWatchdog = false
	// A short read deadline on an otherwise idle connection is directly
	// observable: once it reaches the socket the read loop times out and
	// reports the error. Without the plumbing the read blocks forever and
	// nothing is ever reported.
	cli.ReadTimeout = 150 * time.Millisecond

	conn, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case er := <-cli.Handler.ErrorReports():
		var ne net.Error
		if !errors.As(er.Error, &ne) || !ne.Timeout() {
			t.Fatalf("got %v, want a read timeout", er.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle conn never hit ReadTimeout: timeout not plumbed to the conn")
	}
}

// TestClientWithoutTimeoutsIsUnbounded is the control for the test above:
// with no timeouts configured an idle connection must stay open, so the
// timeout test above cannot pass for some unrelated reason.
func TestClientWithoutTimeoutsIsUnbounded(t *testing.T) {
	ssm := New(serverSettings)
	ssm.mux.HandleFunc("ALL", func(diam.Conn, *diam.Message) {})
	srv := diamtest.NewServer(ssm, dict.Default)
	defer srv.Close()

	cli := newLivenessClient()
	cli.EnableWatchdog = false

	conn, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case er := <-cli.Handler.ErrorReports():
		t.Fatalf("idle conn without timeouts reported %v", er.Error)
	case <-time.After(500 * time.Millisecond):
	}

	m := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	if _, err := m.WriteTo(conn); err != nil {
		t.Fatalf("write without timeouts: %v", err)
	}
}
