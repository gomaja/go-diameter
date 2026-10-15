package sm

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

type stalledWatchdogConn struct {
	*watchdogProbeConn
	entered chan struct{}
	release chan struct{}
}

func (c *stalledWatchdogConn) WriteStream(b []byte, stream uint) (int, error) {
	close(c.entered)
	<-c.release
	return c.watchdogProbeConn.WriteStream(b, stream)
}

func TestWatchdogStalledReceiveStorageIsConstant(t *testing.T) {
	for _, beforeWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "observer", true: "write"}[beforeWrite], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newWatchdogProbeConn()
				signals := newWatchdogSignals()
				entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var writer diam.Conn = c
				if beforeWrite {
					writer = &stalledWatchdogConn{c, entered, release}
				}
				events := make(chan WatchdogEvent, 8)
				w := connWatchdog{conn: c, done: c.closed, signals: &signals,
					interval: func() time.Duration { return loopWatchdogTw },
					send: func() bool {
						return publishDWR(writer, regressionDWR(t), &signals, 0, new(sync.Mutex), nil, func(e WatchdogEvent) {
							events <- e
							if !beforeWrite {
								close(entered)
								<-release
							}
						}, nil)
					}, observe: func(e WatchdogEvent) { events <- e },
				}
				go func() { w.run(); close(exited) }()
				defer func() { unblock(); c.Close(); <-exited }()
				time.Sleep(loopWatchdogTw)
				<-entered
				// All 100,001 receives must complete while the consumer remains
				// stalled. No retained object may be allocated for each receipt.
				allocs := testing.AllocsPerRun(100000, signals.received)
				if allocs != 0 {
					t.Fatalf("stalled receive storage allocates %.2f objects per activity; want constant storage without receive backpressure", allocs)
				}
				unblock()
				synctest.Wait()
				if got := <-events; got != WatchdogRequestSent {
					t.Fatalf("publication event = %s", got)
				}
				time.Sleep(loopWatchdogTw)
				synctest.Wait()
				if got := <-events; got != WatchdogSuspect {
					t.Fatalf("sustained activity changed Pending: %s", got)
				}
			})
		})
	}
}

// RFC 3539 Appendix A OnTimerElapsed sends DWR before SetWatchdog. Time
// spent blocked before publication cannot consume the peer's response window.
func TestWatchdogWriteStallDoesNotConsumeResponseWindow(t *testing.T) {
	for _, activity := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "activity"}[activity], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := &stalledWatchdogConn{newWatchdogProbeConn(), make(chan struct{}), make(chan struct{})}
				signals := newWatchdogSignals()
				events := make(chan WatchdogEvent, 8)
				exited := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(c.release) }) }
				w := connWatchdog{conn: c, done: c.closed, signals: &signals,
					interval: func() time.Duration { return loopWatchdogTw },
					send: func() bool {
						return publishDWR(c, regressionDWR(t), &signals, 0, new(sync.Mutex), nil,
							func(e WatchdogEvent) { events <- e }, nil)
					}, observe: func(e WatchdogEvent) { events <- e },
				}
				go func() { w.run(); close(exited) }()
				defer func() { unblock(); c.Close(); <-exited }()
				time.Sleep(loopWatchdogTw)
				<-c.entered
				time.Sleep(loopWatchdogTw / 2)
				if activity {
					signals.received() // predates successful DWR publication
				}
				time.Sleep(3*loopWatchdogTw - loopWatchdogTw/2)
				unblock()
				synctest.Wait()
				if got := <-events; got != WatchdogRequestSent {
					t.Fatalf("publication event = %s", got)
				}
				select {
				case e := <-events:
					t.Fatalf("peer lost its response window before bytes were published: %s", e)
				default:
				}
				time.Sleep(loopWatchdogTw - time.Nanosecond)
				synctest.Wait()
				select {
				case e := <-events:
					t.Fatalf("event before successful publication + Tw: %s", e)
				default:
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if got := <-events; got != WatchdogSuspect {
					t.Fatalf("publication + Tw: %s, want SUSPECT", got)
				}
			})
		})
	}
}

func TestWatchdogSustainedReceiptsMatchIdleConsumer(t *testing.T) {
	for _, suspect := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "suspect"}[suspect], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := newWatchdogProbeConn()
				idle, stalled := newWatchdogSignals(), newWatchdogSignals()
				request := regressionDWR(t)
				header := *request.Header
				idle.request.Store(&header)
				stalled.request.Store(&header)
				answer := acceptedDWA(t, request, diam.Success)
				states := [2]watchdogState{{pending: true, suspect: suspect}, {pending: true, suspect: suspect}}
				windows := [2]watchdog.Window{{ArmedAt: time.Now(), After: loopWatchdogTw}, {ArmedAt: time.Now(), After: loopWatchdogTw}}
				var events [2][]WatchdogEvent
				loops := [2]connWatchdog{}
				for i, signals := range []*watchdogSignals{&idle, &stalled} {
					loops[i] = connWatchdog{conn: c, signals: signals,
						interval: func() time.Duration { return loopWatchdogTw },
						send:     func() bool { events[i] = append(events[i], WatchdogRequestSent); return true },
						observe:  func(e WatchdogEvent) { events[i] = append(events[i], e) }}
				}
				for batch := range 100 {
					time.Sleep(time.Millisecond)
					for range 1000 {
						idle.received()
						stalled.received()
					}
					if batch == 25 || batch == 75 {
						for _, signals := range []*watchdogSignals{&idle, &stalled} {
							r := signals.receivedMessage(answer)
							kind, _ := processDWAReceipt(c, answer, signals, nil, r)
							if batch == 25 && kind != "" || batch == 75 && kind != diam.ProtocolUnexpectedMessage {
								t.Fatalf("batch %d DWA decision = %s", batch, kind)
							}
						}
					}
					loops[0].advance(&windows[0], &states[0])
				}
				loops[1].advance(&windows[1], &states[1])
				if states[0] != states[1] || windows[0] != windows[1] || !slices.Equal(events[0], events[1]) {
					t.Fatalf("stalled consumer differs from idle: states=%+v windows=%+v events=%v", states, windows, events)
				}
				// Both consumers must use the newest receipt's deadline and
				// retain the older DWA credit when sending the next probe.
				time.Sleep(loopWatchdogTw)
				for i := range loops {
					loops[i].advance(&windows[i], &states[i])
				}
				if !slices.Equal(events[0], events[1]) || events[1][len(events[1])-1] != WatchdogRequestSent {
					t.Fatalf("post-backlog expiry events = %v", events)
				}
			})
		})
	}
}

func TestWatchdogDWAReceiptStorageIsConstant(t *testing.T) {
	signals := newWatchdogSignals()
	answer := acceptedDWA(t, regressionDWR(t), diam.Success)
	allocs := testing.AllocsPerRun(100000, func() {
		r := signals.receivedMessage(answer)
		signals.finishDWA(r, false)
	})
	if allocs != 0 {
		t.Fatalf("DWA receipt storage allocates %.2f objects per decision", allocs)
	}
}

func TestWatchdogObserverStallDoesNotExtendResponseWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newWatchdogProbeConn()
		signals := newWatchdogSignals()
		entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		events := make(chan WatchdogEvent, 8)
		w := connWatchdog{conn: c, done: c.closed, signals: &signals,
			interval: func() time.Duration { return loopWatchdogTw },
			send: func() bool {
				return publishDWR(c, regressionDWR(t), &signals, 0, new(sync.Mutex), nil, func(e WatchdogEvent) {
					events <- e
					close(entered)
					<-release
				}, nil)
			}, observe: func(e WatchdogEvent) { events <- e },
		}
		go func() { w.run(); close(exited) }()
		defer func() { unblock(); c.Close(); <-exited }()
		time.Sleep(loopWatchdogTw)
		<-entered
		if got := <-events; got != WatchdogRequestSent {
			t.Fatalf("publication event = %s", got)
		}
		time.Sleep(3 * loopWatchdogTw)
		unblock()
		synctest.Wait()
		select {
		case e := <-events:
			if e != WatchdogSuspect {
				t.Fatalf("after publication + 3Tw: %s, want SUSPECT", e)
			}
		default:
			t.Fatal("observer backlog extended the peer's response window")
		}
	})
}

type writeThenStallWatchdogConn struct {
	*stalledWatchdogConn
	once sync.Once
}

func (c *writeThenStallWatchdogConn) WriteStream(b []byte, stream uint) (int, error) {
	n, err := c.watchdogProbeConn.WriteStream(b, stream)
	c.once.Do(func() { close(c.entered); <-c.release })
	return n, err
}

// A DWA can reach the receive adapter before the DWR's write call returns.
// Its credit proves publication; subsequent activity keeps its receipt time.
func TestWatchdogDWAAndActivityBeforeWriteReturns(t *testing.T) {
	for _, overdue := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_deadline", true: "overdue"}[overdue], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := &writeThenStallWatchdogConn{stalledWatchdogConn: &stalledWatchdogConn{
					newWatchdogProbeConn(), make(chan struct{}), make(chan struct{}),
				}}
				signals := newWatchdogSignals()
				request := regressionDWR(t)
				events := make(chan WatchdogEvent, 8)
				exited := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(c.release) }) }
				w := connWatchdog{conn: c, done: c.closed, signals: &signals,
					interval: func() time.Duration { return loopWatchdogTw },
					send: func() bool {
						return publishDWR(c, request, &signals, 0, new(sync.Mutex), nil, func(e WatchdogEvent) { events <- e }, nil)
					}, observe: func(e WatchdogEvent) { events <- e },
				}
				go func() { w.run(); close(exited) }()
				defer func() { unblock(); c.Close(); <-exited }()
				time.Sleep(loopWatchdogTw)
				<-c.entered // bytes are published at 50ms; WriteStream has not returned
				time.Sleep(10 * time.Millisecond)
				answer := acceptedDWA(t, request, diam.Success)
				receipt := signals.receivedMessage(answer) // DWA at 60ms
				time.Sleep(10 * time.Millisecond)
				signals.received() // latest activity at 70ms; deadline is 120ms
				if overdue {
					time.Sleep(80 * time.Millisecond)
				} else {
					time.Sleep(20 * time.Millisecond)
				}
				unblock() // write returns at 90ms or 150ms
				synctest.Wait()
				if got := <-events; got != WatchdogRequestSent {
					t.Fatalf("publication event = %s", got)
				}
				if kind, _ := processDWAReceipt(c, answer, &signals, nil, receipt); kind != "" {
					t.Fatalf("DWA decision = %s", kind)
				}
				synctest.Wait()
				if !overdue {
					time.Sleep(30*time.Millisecond - time.Nanosecond)
					synctest.Wait()
					select {
					case e := <-events:
						t.Fatalf("event before latest receipt + Tw: %s", e)
					default:
					}
					time.Sleep(time.Nanosecond)
					synctest.Wait()
				}
				select {
				case e := <-events:
					if e != WatchdogRequestSent {
						t.Fatalf("overdue credited receive deadline: %s", e)
					}
				default:
					t.Fatal("write return replaced the latest receipt time after DWA credit")
				}
			})
		})
	}
}

func TestWatchdogCoalescingRetainsHealthyActivityBeforeInvalidDWA(t *testing.T) {
	signals := newWatchdogSignals()
	signals.received()
	answer := acceptedDWA(t, regressionDWR(t), diam.Success)
	r := signals.receivedMessage(answer)
	signals.finishDWA(r, false)
	state := watchdogState{pending: true, suspect: true}
	window := watchdog.Window{ArmedAt: time.Now(), After: time.Second}
	var events []WatchdogEvent
	w := connWatchdog{signals: &signals, interval: func() time.Duration { return time.Second },
		observe: func(e WatchdogEvent) { events = append(events, e) }}
	alive, waiting := w.advance(&window, &state)
	if !alive || waiting || state.suspect || !state.pending || !slices.Equal(events, []WatchdogEvent{WatchdogRecovered}) || !window.ArmedAt.Equal(r.at) {
		t.Fatalf("coalesced healthy activity followed by invalid DWA: alive=%v waiting=%v state=%+v events=%v window=%+v", alive, waiting, state, events, window)
	}
}

func TestWatchdogOutOfOrderDWADecisions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signals := newWatchdogSignals()
		answer := acceptedDWA(t, regressionDWR(t), diam.Success)
		window := watchdog.Window{ArmedAt: time.Now(), After: loopWatchdogTw}
		state := watchdogState{pending: true, suspect: true}
		time.Sleep(10 * time.Millisecond)
		earlier := signals.receivedMessage(answer)
		time.Sleep(10 * time.Millisecond)
		later := signals.receivedMessage(answer)
		signals.finishDWA(later, true)
		time.Sleep(3 * loopWatchdogTw)
		var events []WatchdogEvent
		w := connWatchdog{signals: &signals, interval: func() time.Duration { return loopWatchdogTw },
			send:    func() bool { events = append(events, WatchdogRequestSent); return true },
			observe: func(e WatchdogEvent) { events = append(events, e) }}
		alive, waiting := w.advance(&window, &state)
		if !alive || !waiting || !state.pending || !state.suspect || len(events) != 0 {
			t.Fatalf("earlier unfinished decision was overtaken: alive=%v waiting=%v state=%+v events=%v", alive, waiting, state, events)
		}
		signals.finishDWA(earlier, false)
		alive, waiting = w.advance(&window, &state)
		if !alive || waiting || state.suspect || !state.pending || !slices.Equal(events, []WatchdogEvent{WatchdogRecovered, WatchdogRequestSent}) {
			t.Fatalf("out-of-order decisions lost DWA credit: alive=%v waiting=%v state=%+v events=%v", alive, waiting, state, events)
		}
		if signals.validating != 0 || queuedWatchdogCredits(&signals) != 0 {
			t.Fatalf("drained decisions retained validation or credit: pending=%d", signals.validating)
		}
	})
}

// Activity predating publication cannot redraw an already armed probe's
// jittered response interval, even when the new draw would be shorter.
func TestWatchdogPrepublicationActivityPreservesJitteredWindow(t *testing.T) {
	for _, simultaneous := range []bool{false, true} {
		t.Run(map[bool]string{false: "earlier", true: "same_timestamp"}[simultaneous], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				signals := newWatchdogSignals()
				signals.received()
				if !simultaneous {
					time.Sleep(time.Millisecond)
				}
				signals.published()
				publication := time.Now()
				window := watchdog.Window{ArmedAt: publication, After: 8 * time.Second}
				state := watchdogState{pending: true}
				draws := 0
				w := connWatchdog{signals: &signals, interval: func() time.Duration { draws++; return 6 * time.Second },
					observe: func(e WatchdogEvent) { t.Fatalf("unexpected health event: %s", e) }}
				alive, waiting := w.advance(&window, &state)
				if !alive || waiting || window.ArmedAt != publication || window.After != 8*time.Second || draws != 0 {
					t.Fatalf("prepublication receipt replaced jittered response window: alive=%v waiting=%v window=%+v draws=%d", alive, waiting, window, draws)
				}
			})
		})
	}
}

func TestWatchdogPostpublicationActivityRedrawsJitteredWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signals := newWatchdogSignals()
		signals.published()
		publication := time.Now()
		signals.received() // same timestamp, but received after publication
		window := watchdog.Window{ArmedAt: publication, After: 8 * time.Second}
		state := watchdogState{pending: true}
		draws := 0
		w := connWatchdog{signals: &signals, interval: func() time.Duration { draws++; return 6 * time.Second },
			observe: func(e WatchdogEvent) { t.Fatalf("unexpected health event: %s", e) }}
		alive, waiting := w.advance(&window, &state)
		if !alive || waiting || window.ArmedAt != publication || window.After != 6*time.Second || draws != 1 {
			t.Fatalf("postpublication receipt did not reset Tw: alive=%v waiting=%v window=%+v draws=%d", alive, waiting, window, draws)
		}
	})
}
