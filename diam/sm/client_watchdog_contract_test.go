package sm

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type clientReviewDualDoneConn struct {
	*watchdogProbeConn
	notify      chan struct{}
	dispatched  chan struct{}
	notifyCalls atomic.Int32
}

func (c *clientReviewDualDoneConn) CloseNotify() <-chan struct{} {
	c.notifyCalls.Add(1)
	return c.notify
}
func (c *clientReviewDualDoneConn) DispatchDone() <-chan struct{} { return c.dispatched }

func TestClientWatchdogUsesCloseNotifierOverDispatchDone(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "direct"
		if wrapped {
			name = "unwrapped"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cli := newLivenessClient(t)
				cli.WatchdogInterval = time.Hour
				c := &clientReviewDualDoneConn{watchdogProbeConn: newWatchdogProbeConn(),
					notify: make(chan struct{}), dispatched: make(chan struct{})}
				var conn diam.Conn = c
				if wrapped {
					conn = unwrapTestConn{conn}
				}
				state := primeClientTestCore(t, cli, conn)
				w := state.watchdogState()
				defer func() { close(c.dispatched); c.Close() }()
				close(c.notify)
				synctest.Wait()
				if c.notifyCalls.Load() == 0 {
					t.Fatal("client did not discover CloseNotify")
				}
				select {
				case <-w.exited:
				default:
					t.Fatal("client watchdog remained running after CloseNotify")
				}
				if got := len(c.writes); got != 0 {
					t.Fatalf("DWR writes after CloseNotify = %d, want zero", got)
				}
			})
		})
	}
}

func TestClientWatchdogSerializesRequestAndDWAEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli := newLivenessClient(t)
		c := &blockingPublishWatchdogConn{watchdogProbeConn: newWatchdogProbeConn(),
			entered: make(chan struct{}), release: make(chan struct{}), written: make(chan []byte, 1)}
		unblock := sync.OnceFunc(func() { close(c.release) })
		defer unblock()
		observations := make(chan WatchdogEvent, 2)
		cli.OnWatchdogEvent = func(event WatchdogEvent) { observations <- event }
		state := primeClientTestCore(t, cli, c)
		requestDone := make(chan struct{})
		go func() { expireClientTestWatchdog(state); close(requestDone) }()
		<-c.entered
		request, err := diam.ReadMessage(bytes.NewReader(<-c.written), c.Dictionary())
		if err != nil {
			unblock()
			<-requestDone
			t.Fatal(err)
		}
		dwa, err := base.BuildDWA(request, baseSettings(clientSettings))
		if err != nil {
			unblock()
			<-requestDone
			t.Fatal(err)
		}
		state.mu.Lock()
		requestObservation := state.observerTail
		state.mu.Unlock()
		dwaDone := make(chan struct{})
		go func() { cli.Handler.ServeDIAM(c, dwa); close(dwaDone) }()
		synctest.Wait()
		state.mu.Lock()
		answerObservation := state.observerTail
		state.mu.Unlock()
		if answerObservation == requestObservation {
			unblock()
			<-requestDone
			<-dwaDone
			t.Fatal("DWA did not reach its production observation checkpoint")
		}
		select {
		case e := <-observations:
			t.Fatalf("observer overtook the blocked request write: %s", e)
		default:
		}
		unblock()
		<-requestDone
		<-dwaDone
		for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogAnswerReceived} {
			select {
			case got := <-observations:
				if got != want {
					t.Fatalf("watchdog event = %q, want %q", got, want)
				}
			default:
				t.Fatalf("missing watchdog event %q", want)
			}
		}
	})
}

func TestClientWatchdogAdapterStateEventsHoldPublicationLock(t *testing.T) {
	cli := newLivenessClient(t)
	c := newWatchdogProbeConn()
	state := primeClientTestCore(t, cli, c)
	w := state.watchdogState()
	type observation struct {
		event  WatchdogEvent
		locked bool
	}
	events := make(chan observation, 8)
	cli.OnWatchdogEvent = func(event WatchdogEvent) {
		locked := !w.mu.TryLock()
		if !locked {
			w.mu.Unlock()
		}
		events <- observation{event, locked}
	}
	want := func(event WatchdogEvent) {
		t.Helper()
		select {
		case got := <-events:
			if got.event != event || !got.locked {
				t.Fatalf("watchdog observation = %+v, want %s under publication lock", got, event)
			}
		default:
			t.Fatalf("missing watchdog event %s", event)
		}
	}
	expireClientTestWatchdog(state)
	want(WatchdogRequestSent)
	expireClientTestWatchdog(state)
	want(WatchdogSuspect)
	receiveClientTestActivity(state)
	want(WatchdogRecovered)
	expireClientTestWatchdog(state)
	want(WatchdogSuspect)
	expireClientTestWatchdog(state)
	want(WatchdogTimedOut)
	if !c.Closed() {
		t.Fatal("DOWN did not close the connection")
	}
}
