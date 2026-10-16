package sm

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestClientCoreWatchdogWriteStallDoesNotConsumeResponseWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli := newLivenessClient(t)
		c := &blockingPublishWatchdogConn{watchdogProbeConn: newWatchdogProbeConn(),
			entered: make(chan struct{}), release: make(chan struct{})}
		events := make(chan WatchdogEvent, 16)
		cli.OnWatchdogEvent = func(e WatchdogEvent) { events <- e }
		state := primeClientTestCore(t, cli, c)
		done := make(chan struct{})
		go func() { expireClientTestWatchdog(state); close(done) }()
		<-c.entered
		time.Sleep(3 * cli.WatchdogInterval)
		synctest.Wait()
		if state.snapshot().Watchdog().Pending || c.Closed() || len(events) != 0 {
			t.Fatal("unpublished DWR consumed the peer's response window")
		}
		close(c.release)
		<-done
		synctest.Wait()
		if e := <-events; e != WatchdogRequestSent {
			t.Fatalf("publication event = %s", e)
		}
		time.Sleep(cli.WatchdogInterval - time.Nanosecond)
		synctest.Wait()
		if len(events) != 0 {
			t.Fatal("watchdog expired before successful publication + Tw")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if e := <-events; e != WatchdogSuspect {
			t.Fatalf("publication + Tw event = %s", e)
		}
		c.Close()
		synctest.Wait()
	})
}

func TestClientCoreWatchdogBlockedWriteAllowsInboundDispatch(t *testing.T) {
	cli := newLivenessClient(t)
	c := &blockingPublishWatchdogConn{watchdogProbeConn: newWatchdogProbeConn(),
		entered: make(chan struct{}), release: make(chan struct{})}
	state := primeClientTestCore(t, cli, c)
	done := make(chan struct{})
	go func() { expireClientTestWatchdog(state); close(done) }()
	<-c.entered
	if !state.mu.TryLock() {
		close(c.release)
		<-done
		t.Fatal("writer held the core mutation lock")
	}
	state.mu.Unlock()
	dispatched := make(chan struct{}, 1)
	cli.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched <- struct{}{} }))
	cli.Handler.ServeDIAM(c, diam.NewRequest(999, 4, c.Dictionary()).Answer(diam.Success))
	select {
	case <-dispatched:
	default:
		close(c.release)
		<-done
		t.Fatal("application dispatch waited for a blocked DWR")
	}
	close(c.release)
	<-done
}

type capturedClientWatchdogConn struct {
	*watchdogProbeConn
	wire chan []byte
}

func (c *capturedClientWatchdogConn) WriteStream(b []byte, stream uint) (int, error) {
	c.wire <- append([]byte(nil), b...)
	return c.watchdogProbeConn.WriteStream(b, stream)
}

func TestClientCoreWatchdogConcurrentDuplicateDWA(t *testing.T) {
	cli := newLivenessClient(t)
	// This test explicitly expires one selected watchdog timer; supervision
	// must not expire again while the concurrent replies are being scheduled.
	cli.WatchdogInterval = time.Hour
	inner := &capturedClientWatchdogConn{newWatchdogProbeConn(), make(chan []byte, 1)}
	logs := logtest.New()
	c := loggedNotifyingWatchdogConn{loggedWatchdogConn{inner, logs.Logger()}, inner.closed}
	events := make(chan WatchdogEvent, 32)
	cli.OnWatchdogEvent = func(e WatchdogEvent) { events <- e }
	state := primeClientTestCore(t, cli, c)
	expireClientTestWatchdog(state)
	request, err := diam.ReadMessage(bytes.NewReader(<-inner.wire), cli.Dict)
	if err != nil {
		t.Fatal(err)
	}
	if e := <-events; e != WatchdogRequestSent {
		t.Fatalf("publication event = %s", e)
	}
	const copies = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range copies {
		answer := acceptedDWA(t, request, diam.Success)
		wg.Go(func() {
			<-start
			cli.Handler.ServeDIAM(c, answer)
		})
	}
	close(start)
	wg.Wait()
	var observed []WatchdogEvent
	for len(events) != 0 {
		observed = append(observed, <-events)
	}
	after := state.snapshot().Watchdog()
	if len(observed) != 1 || observed[0] != WatchdogAnswerReceived || after.Pending {
		t.Fatalf("concurrent DWA callbacks=%v watchdog=%+v; want one answer and no pending probe", observed, after)
	}
	if got := len(logs.RecordsWithMessage("sm: unhandled answer discarded")); got != copies-1 {
		t.Fatalf("duplicate DWA warnings = %d, want %d", got, copies-1)
	}
}

func TestClientCoreWatchdogStopDisposesSelectedWriter(t *testing.T) {
	cli := newLivenessClient(t)
	c := newWatchdogProbeConn()
	state := primeClientTestCore(t, cli, c)
	timer := state.snapshot().Timer(protocol.WatchdogTimer)
	batch := state.prepare(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer,
		Token: timer.Token, At: timer.Deadline})
	state.watchdogState().stop()
	state.run(batch)
	if len(c.writes) != 0 || c.Closed() || len(state.snapshot().Controls()) != 0 {
		t.Fatal("stopped watchdog published a selected writer or retained its reservation")
	}
}

func TestClientCoreWatchdogAttemptFailureCrossesClosing(t *testing.T) {
	for _, result := range []struct {
		name  string
		count int
		err   error
	}{
		{"short-count", -1, nil},
		{"transport-failure", 0, errors.New("synthetic DWR transport failure")},
		{"full-count-error", 0, errors.New("synthetic DWR full-count failure")},
		{"partial-closing-error", 1, diam.ErrConnectionClosing},
		{"partial-completed-error", 1, diam.ErrRequestCompleted},
		{"partial-retired-error", 1, diam.ErrConnectionRetired},
	} {
		for _, closing := range []string{"local", "peer"} {
			t.Run(result.name+"/"+closing, func(t *testing.T) {
				cli := newLivenessClient(t)
				cli.WatchdogInterval = time.Hour
				events := make(chan WatchdogEvent, 8)
				cli.OnWatchdogEvent = func(e WatchdogEvent) { events <- e }
				c := &acceptedWriterResultConn{acceptedAdapterNotifyConn: &acceptedAdapterNotifyConn{
					handshakeConn: newHandshakeConn(), closed: make(chan struct{})},
					entered: make(chan struct{}), release: make(chan struct{}), count: result.count, err: result.err}
				if result.name == "full-count-error" {
					m, err := cli.makeDWR(0)
					if err != nil {
						t.Fatal(err)
					}
					c.count = m.Len()
				}
				state := primeClientTestCore(t, cli, c)
				w := state.watchdogState()
				var once sync.Once
				unblock := func() { once.Do(func() { close(c.release) }) }
				t.Cleanup(func() { unblock(); c.Close(); w.stop(); <-w.exited })
				written := make(chan struct{})
				go func() { expireClientTestWatchdog(state); close(written) }()
				protocolGenerationAwait(t, c.entered)
				if controls := state.snapshot().Controls(); len(controls) != 1 || controls[0].Writers != 1 {
					t.Fatalf("blocked DWR did not pin its lease: %+v", controls)
				}
				finished := beginClientWriterClosing(t, state, closing)
				unblock()
				protocolGenerationAwait(t, written)
				if state.snapshot().Phase() != protocol.Closed || !c.Closed() {
					t.Errorf("attempted DWR failure was skipped: phase=%v closed=%t", state.snapshot().Phase(), c.Closed())
				}
				select {
				case err := <-finished:
					if closing == "local" && !errors.Is(err, ErrDisconnectClosed) {
						t.Errorf("Disconnect=%v, want ErrDisconnectClosed", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("attempted DWR failure did not release the Closing caller")
				}
				if controls := state.snapshot().Controls(); len(controls) != 0 {
					t.Errorf("completed DWR retained a core lease or later DPR: %+v", controls)
				}
				state.mu.Lock()
				selected := len(state.writes)
				state.mu.Unlock()
				if selected != 0 || len(events) != 0 || len(c.writes) != 0 {
					t.Errorf("failed stopped writer retained tickets=%d or emitted events=%d writes=%d", selected, len(events), len(c.writes))
				}
				state.apply(protocol.Input{Kind: protocol.Abort})
			})
		}
	}
}

func beginClientWriterClosing(t *testing.T, state *acceptedHandshake, closing string) <-chan error {
	t.Helper()
	finished := make(chan error, 1)
	if closing == "local" {
		go func() { finished <- state.sm.Disconnect(state.conn, DisconnectBusy, time.Hour) }()
	} else {
		dpr := acceptedDPR(t)
		go func() { state.sm.ServeDIAM(state.conn, dpr); finished <- nil }()
	}
	deadline := time.Now().Add(10 * time.Second)
	for state.snapshot().Phase() != protocol.Closing || !state.watchdogState().stopped.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Closing did not stop observations while the writer was blocked")
		}
		time.Sleep(time.Millisecond)
	}
	return finished
}

func TestClientCoreWatchdogGateRejectionStaysSkipped(t *testing.T) {
	for _, rejected := range []struct {
		name string
		err  error
	}{
		{"closing", diam.ErrConnectionClosing}, {"completed", diam.ErrRequestCompleted}, {"retired", diam.ErrConnectionRetired},
	} {
		for _, closing := range []string{"local", "peer"} {
			t.Run(rejected.name+"/"+closing, func(t *testing.T) {
				cli := newLivenessClient(t)
				cli.WatchdogInterval = time.Hour
				events := make(chan WatchdogEvent, 8)
				cli.OnWatchdogEvent = func(e WatchdogEvent) { events <- e }
				c := &acceptedWriterResultConn{acceptedAdapterNotifyConn: &acceptedAdapterNotifyConn{
					handshakeConn: newHandshakeConn(), closed: make(chan struct{})},
					entered: make(chan struct{}), release: make(chan struct{}), err: rejected.err}
				state := primeClientTestCore(t, cli, c)
				w := state.watchdogState()
				var once sync.Once
				unblock := func() { once.Do(func() { close(c.release) }) }
				t.Cleanup(func() { unblock(); c.Close(); w.stop(); <-w.exited })
				written := make(chan struct{})
				go func() { expireClientTestWatchdog(state); close(written) }()
				protocolGenerationAwait(t, c.entered)
				finished := beginClientWriterClosing(t, state, closing)
				unblock()
				protocolGenerationAwait(t, written)
				if state.snapshot().Phase() != protocol.Closing || c.Closed() {
					t.Errorf("zero-byte gate rejection became a transport failure: phase=%v closed=%t", state.snapshot().Phase(), c.Closed())
				}
				for _, control := range state.snapshot().Controls() {
					if control.Command == diam.DeviceWatchdog {
						t.Errorf("gate rejection retained a DWR lease: %+v", control)
					}
				}
				if len(events) != 0 {
					t.Errorf("gate rejection emitted %d watchdog events", len(events))
				}
				state.apply(protocol.Input{Kind: protocol.Abort})
				_ = protocolGenerationAwait(t, finished)
			})
		}
	}
}
