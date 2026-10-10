package sm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestClientCancellationRejectsLateCEA(t *testing.T) {
	cli := newLivenessClient(t)
	var called atomic.Bool
	cfg := *clientSettings
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { called.Store(true) }
	cli.Handler = mustNewStateMachine(t, &cfg)
	c := newHandshakeConn()
	closing, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	c.afterWrite = func(int32) { <-release }
	c.afterClose = func() { close(closing); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	activity := newWatchdogActivity()
	activity.capabilities = cli.capabilitySettings(nil)
	activity.advertised = base.AdvertisedApplicationIDs(activity.capabilities)
	done := make(chan error, 1)
	go func() { _, err := cli.handshakeContext(ctx, c, activity); done <- err }()
	t.Cleanup(func() {
		cancel()
		unblock()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("dial = %v, want context.Canceled", err)
		}
	})
	var cer *diam.Message
	select {
	case b := <-c.writes:
		var err error
		cer, err = diam.ReadMessage(bytes.NewReader(b), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CER write did not start")
	}
	cancel()
	select {
	case <-closing:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not start closing")
	}
	cea, err := base.BuildCEA(cer, activity.capabilities, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	handleCEA(cli.Handler, activity)(c, cea)
	if called.Load() {
		t.Error("late CEA ran OnHandshake after cancellation started closing")
	}
	if _, ok := smpeer.FromContext(c.Context()); ok {
		t.Error("late CEA stored peer metadata after cancellation")
	}
	unblock()
	// Cleanup joins the dial, including its cancellation callback.
}

func TestClientRetransmitTimerStartsAfterWrite(t *testing.T) {
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.RetransmitInterval = 50 * time.Millisecond
	cli.MaxRetransmits = 3
	c := newHandshakeConn()
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	c.afterWrite = func(seq int32) {
		if seq == 1 {
			<-release
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	activity := newWatchdogActivity()
	activity.capabilities = cli.capabilitySettings(nil)
	done := make(chan error, 1)
	go func() { _, err := cli.handshakeContext(ctx, c, activity); done <- err }()
	t.Cleanup(func() {
		cancel()
		unblock()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("dial = %v, want context.Canceled", err)
		}
	})
	select {
	case <-c.writes:
	case <-time.After(time.Second):
		t.Fatal("first CER not written")
	}
	// Hold the write beyond an interval, then release it. A running timer would
	// already have a stale tick buffered under asynctimerchan=1.
	<-time.After(2 * cli.RetransmitInterval)
	unblock()
	select {
	case <-c.writes:
		t.Fatal("CER retransmitted before its post-write interval")
	case <-time.After(cli.RetransmitInterval / 2):
	}
	select {
	case <-c.writes:
	case <-time.After(time.Second):
		t.Fatal("CER timer was not reset after write")
	}
}

func TestClientLegacyTLSHandshakeErrors(t *testing.T) {
	for _, method := range []string{"DialTLS", "DialNetworkTLS", "DialTLSTimeout", "DialTLSExt"} {
		t.Run(method, func(t *testing.T) {
			srv := diamtest.NewUnstartedServer(mustNewStateMachine(t, serverSettings), dict.Default)
			srv.StartTLS()
			defer srv.Close()
			cli := newLivenessClient(t)
			cli.InbandSecurityID = 1
			result := make(chan error, 1)
			go func() {
				var c diam.Conn
				var err error
				switch method {
				case "DialTLS":
					c, err = cli.DialTLS(srv.Addr, "", "")
				case "DialNetworkTLS":
					c, err = cli.DialNetworkTLS("tcp", srv.Addr, "", "", nil)
				case "DialTLSTimeout":
					c, err = cli.DialTLSTimeout(srv.Addr, "", "", 0)
				case "DialTLSExt":
					c, err = cli.DialTLSExt("tcp", srv.Addr, "", "", 0, nil)
				}
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil || !strings.HasPrefix(err.Error(), "TLS handshake before CER:") {
					t.Fatalf("legacy TLS error = %v, want handshake-before-CER error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("legacy TLS handshake did not return")
			}
		})
	}
}

type abortObservedConn struct {
	net.Conn
	aborted atomic.Bool
}

func (c *abortObservedConn) Abort() error { c.aborted.Store(true); return c.Close() }

type wrappedDialConn struct{ net.Conn }

func (c wrappedDialConn) NetConn() net.Conn { return c.Conn }

func TestAbortDialTransportAndClosedState(t *testing.T) {
	for _, kind := range []string{"plain", "abort", "wrapped TLS"} {
		t.Run(kind, func(t *testing.T) {
			rw, peer := net.Pipe()
			defer closeDialTest(t, peer)
			transport := &abortObservedConn{Conn: rw}
			conn := rw
			if kind == "abort" {
				conn = transport
			}
			if kind == "wrapped TLS" {
				conn = tls.Client(wrappedDialConn{transport}, &tls.Config{MinVersion: tls.VersionTLS12})
			}
			srv := &diam.Server{}
			c, err := srv.NewConn(conn)
			if err != nil {
				t.Fatal(err)
			}
			abortDial(c)
			if kind != "plain" && !transport.aborted.Load() {
				t.Error("underlying transport was not aborted")
			}
			if !c.Closed() {
				t.Error("Diameter Closed state was not published")
			}
			select {
			case <-c.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
			case <-time.After(time.Second):
				t.Fatal("connection dispatcher did not stop")
			}
		})
	}
}
