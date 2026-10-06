package sm

import (
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

type watchdogProbeConn struct {
	testLocalAddrDiamConn
	writes chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newWatchdogProbeConn() *watchdogProbeConn {
	return &watchdogProbeConn{writes: make(chan struct{}, 8), closed: make(chan struct{})}
}

func (c *watchdogProbeConn) Write(b []byte) (int, error) {
	c.writes <- struct{}{}
	return len(b), nil
}
func (c *watchdogProbeConn) WriteStream(b []byte, _ uint) (int, error) {
	return c.Write(b)
}
func (c *watchdogProbeConn) Close()                       { c.once.Do(func() { close(c.closed) }) }
func (c *watchdogProbeConn) CloseNotify() <-chan struct{} { return c.closed }

func TestWatchdogOneOutstandingRequestAndStateOrder(t *testing.T) {
	cli := newLivenessClient(t)
	cli.WatchdogInterval = 30 * time.Millisecond
	cli.MaxRetransmits = 4
	cli.RetransmitInterval = time.Millisecond
	events := make(chan WatchdogEvent, 8)
	cli.OnWatchdogEvent = func(event WatchdogEvent) { events <- event }
	c := newWatchdogProbeConn()
	done := make(chan struct{})
	go func() {
		cli.watchdog(c, make(chan struct{}, 1), newWatchdogActivity())
		close(done)
	}()
	defer func() { c.Close(); <-done }()

	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogSuspect, WatchdogTimedOut} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing watchdog event %q", want)
		}
	}
	select {
	case <-c.closed:
	case <-time.After(time.Second):
		t.Fatal("DOWN did not close connection")
	}
	if n := len(c.writes); n != 1 {
		t.Fatalf("wrote %d DWRs, want one outstanding request", n)
	}
}

func TestWatchdogRecoversFromSuspectOnNonDWATraffic(t *testing.T) {
	cli := newLivenessClient(t)
	cli.WatchdogInterval = 40 * time.Millisecond
	events := make(chan WatchdogEvent, 8)
	cli.OnWatchdogEvent = func(event WatchdogEvent) { events <- event }
	activity := newWatchdogActivity()
	c := newWatchdogProbeConn()
	done := make(chan struct{})
	go func() {
		cli.watchdog(c, activity.dwac, activity)
		close(done)
	}()
	defer func() { c.Close(); <-done }()
	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogSuspect} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing event %q", want)
		}
	}
	activity.last.Store(time.Now().UnixNano())
	activity.signal <- struct{}{}
	select {
	case got := <-events:
		if got != WatchdogRecovered {
			t.Fatalf("event = %q, want recovered", got)
		}
	case <-time.After(time.Second):
		t.Fatal("non-DWA traffic did not recover SUSPECT")
	}
	select {
	case <-c.closed:
		t.Fatal("recovered connection closed")
	default:
	}
}

func TestWatchdogRecoversFromSuspectOnAnswer(t *testing.T) {
	type request struct {
		c diam.Conn
		m *diam.Message
	}
	requests := make(chan request, 4)
	serverSM := mustNewStateMachine(t, serverSettings)
	serverSM.mux.HandleIdx(baseDWRIdx, handshakeOK(func(c diam.Conn, m *diam.Message) {
		requests <- request{c, m}
	}))
	srv := diamtest.NewServer(serverSM, dict.Default)
	defer srv.Close()
	events := make(chan WatchdogEvent, 12)
	cli := newLivenessClient(t)
	cli.WatchdogInterval = 50 * time.Millisecond
	cli.MaxRetransmits = 4
	cli.RetransmitInterval = time.Millisecond
	cli.OnWatchdogEvent = func(event WatchdogEvent) { events <- event }
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var first request
	select {
	case first = <-requests:
	case <-time.After(time.Second):
		t.Fatal("no initial DWR")
	}
	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogSuspect} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing event %q", want)
		}
	}
	answer := first.m.Answer(diam.Success)
	mustSMClientAVP(t, answer, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("server"))
	mustSMClientAVP(t, answer, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	if _, err := answer.WriteTo(first.c); err != nil {
		t.Fatal(err)
	}
	seenRecovered := false
	deadline := time.After(time.Second)
	for !seenRecovered {
		select {
		case got := <-events:
			switch got {
			case WatchdogRecovered:
				seenRecovered = true
			case WatchdogTimedOut:
				t.Fatal("connection closed after receiving DWA in SUSPECT")
			}
		case <-deadline:
			t.Fatal("DWA did not recover SUSPECT connection")
		}
	}
	select {
	case <-requests:
		// A new Tw expiration may send a new DWR after the first was answered.
	case <-time.After(time.Second):
		t.Fatal("watchdog did not resume after recovery")
	}
	select {
	case <-c.(diam.CloseNotifier).CloseNotify():
		t.Fatal("recovered connection closed")
	default:
	}
}
