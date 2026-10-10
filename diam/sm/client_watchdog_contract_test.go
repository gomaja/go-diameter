package sm

import (
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
				c := &clientReviewDualDoneConn{
					watchdogProbeConn: newWatchdogProbeConn(),
					notify:            make(chan struct{}), dispatched: make(chan struct{}),
				}
				// RFC 3539 Appendix A: the client adapter must stop when its
				// established CloseNotifier reports the connection down.
				close(c.notify)
				var conn diam.Conn = c
				if wrapped {
					conn = unwrapTestConn{conn}
				}
				activity := newWatchdogActivity()
				exited := make(chan struct{})
				go func() {
					cli.watchdog(conn, activity.dwac, activity)
					close(exited)
				}()
				defer func() {
					close(c.dispatched)
					c.Close()
					<-exited
				}()
				synctest.Wait()
				if got := c.notifyCalls.Load(); got != 1 {
					t.Fatalf("CloseNotify calls = %d, want one", got)
				}
				select {
				case <-exited:
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
	cli := newLivenessClient(t)
	c := &blockingPublishWatchdogConn{
		watchdogProbeConn: newWatchdogProbeConn(),
		entered:           make(chan struct{}), release: make(chan struct{}),
	}
	type observation struct {
		event    WatchdogEvent
		lockHeld bool
	}
	observations := make(chan observation, 2)
	cli.OnWatchdogEvent = func(event WatchdogEvent) {
		locked := !cli.watchdogEventMu.TryLock()
		if !locked {
			cli.watchdogEventMu.Unlock()
		}
		observations <- observation{event, locked}
	}
	requestDone := make(chan bool, 1)
	go func() { requestDone <- cli.dwr(c, 0) }()
	<-c.entered
	// RFC 6733 §5.6 R-Open: a DWA observer must not publish before its
	// request. Holding the same mutex through write and both event callbacks
	// proves the order without relying on goroutine scheduling.
	if cli.watchdogEventMu.TryLock() {
		cli.watchdogEventMu.Unlock()
		close(c.release)
		<-requestDone
		t.Fatal("watchdog event lock was free during the DWR write")
	}
	dwa, err := base.BuildDWA(regressionDWR(t), baseSettings(serverSettings))
	if err != nil {
		close(c.release)
		<-requestDone
		t.Fatal(err)
	}
	dwaHandler := handleDWA(cli.Handler, make(chan struct{}, 1), cli.observeWatchdog)
	dwaStarted := make(chan struct{})
	dwaDone := make(chan struct{})
	go func() {
		close(dwaStarted)
		dwaHandler.ServeDIAM(c, dwa)
		close(dwaDone)
	}()
	<-dwaStarted
	close(c.release)
	if !<-requestDone {
		t.Fatal("DWR publication failed")
	}
	<-dwaDone
	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogAnswerReceived} {
		select {
		case got := <-observations:
			if got.event != want || !got.lockHeld {
				t.Fatalf("watchdog event = %q, lock held = %t; want %q with lock held", got.event, got.lockHeld, want)
			}
		default:
			t.Fatalf("missing watchdog event %q", want)
		}
	}
}

func TestClientWatchdogAdapterStateEventsHoldPublicationLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli := newLivenessClient(t)
		const tw = 50 * time.Millisecond
		cli.WatchdogInterval = tw
		c := newWatchdogProbeConn()
		activity := newWatchdogActivity()
		type observation struct {
			event    WatchdogEvent
			lockHeld bool
		}
		events := make(chan observation, 8)
		cli.OnWatchdogEvent = func(event WatchdogEvent) {
			locked := !cli.watchdogEventMu.TryLock()
			if !locked {
				cli.watchdogEventMu.Unlock()
			}
			events <- observation{event, locked}
		}
		exited := make(chan struct{})
		go func() {
			cli.watchdog(c, activity.dwac, activity)
			close(exited)
		}()
		synctest.Wait()
		defer func() { c.Close(); <-exited }()
		want := func(event WatchdogEvent) {
			t.Helper()
			select {
			case got := <-events:
				if got.event != event || !got.lockHeld {
					t.Fatalf("watchdog event = %q, lock held = %t; want %q with lock held", got.event, got.lockHeld, event)
				}
			default:
				t.Fatalf("missing watchdog event %q", event)
			}
		}

		time.Sleep(tw)
		synctest.Wait()
		want(WatchdogRequestSent)
		time.Sleep(tw)
		synctest.Wait()
		want(WatchdogSuspect)
		// RFC 3539 Appendix A: traffic recovers SUSPECT while Pending stays set.
		activity.received()
		synctest.Wait()
		want(WatchdogRecovered)
		time.Sleep(tw)
		synctest.Wait()
		want(WatchdogSuspect)
		time.Sleep(tw)
		synctest.Wait()
		want(WatchdogTimedOut)
		select {
		case <-exited:
		default:
			t.Fatal("client watchdog remained running after DOWN")
		}
	})
}
