package sm

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

type watchdogTiming struct {
	floor  time.Duration
	jitter time.Duration
}

func (t *watchdogTiming) parameters() (floor, jitter time.Duration) {
	if t != nil {
		return t.floor, t.jitter
	}
	return watchdog.MinimumTw, watchdog.DefaultJitter
}

func jitteredTw(twinit, jitter time.Duration) time.Duration {
	return watchdog.Tw(twinit, jitter, rand.Int63n)
}

type watchdogSignals struct {
	signal  chan struct{}
	last    atomic.Int64
	dwac    chan struct{}
	request atomic.Pointer[diam.Header]
}

func newWatchdogSignals() watchdogSignals {
	return watchdogSignals{signal: make(chan struct{}, 1), dwac: make(chan struct{}, 1)}
}

func (s *watchdogSignals) received() {
	// RFC 3539 §3.4.1 [2]: any received AAA message resets Tw.
	s.last.Store(time.Now().UnixNano())
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

func isBaseDWA(m *diam.Message) bool {
	return m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.DeviceWatchdog &&
		m.Header.CommandFlags&diam.RequestFlag == 0
}

// connectionDone honors the first wrapper exposing either lifecycle interface.
// At the same layer DispatchDone takes precedence and avoids CloseNotify's TCP
// read pump. An outer CloseNotifier still intercepts closure.
func connectionDone(c diam.Conn) <-chan struct{} {
	for c != nil {
		switch n := c.(type) {
		case interface{ DispatchDone() <-chan struct{} }:
			return n.DispatchDone()
		case diam.CloseNotifier:
			return n.CloseNotify()
		case interface{ Unwrap() diam.Conn }:
			c = n.Unwrap()
		default:
			return nil
		}
	}
	return nil
}

func publishDWR(c diam.Conn, m *diam.Message, signals *watchdogSignals, stream uint, mu *sync.Mutex, stopped *atomic.Bool, emit func(WatchdogEvent), failed func(error)) bool {
	// RFC 6733 §5.6: entering Closing excludes further DWRs. Serialize the
	// check with the write and request event so a fast answer cannot overtake it.
	mu.Lock()
	if c.Closed() || stopped != nil && stopped.Load() {
		mu.Unlock()
		return false
	}
	// RFC 6733 §§3, 6.2.1: retain both identifiers on this connection before
	// writing, since an answer can arrive before WriteToStream returns.
	header := *m.Header
	signals.request.Store(&header)
	if _, err := m.WriteToStream(c, stream); err != nil {
		if c.Closed() || stopped != nil && stopped.Load() {
			mu.Unlock()
			return false
		}
		emit(WatchdogWriteFailed)
		mu.Unlock()
		if failed != nil {
			failed(err)
		} else {
			logMessage(c, m, slog.LevelError, "sm: watchdog request failed; closing connection", err)
			c.Close()
		}
		return false
	}
	if c.Closed() || stopped != nil && stopped.Load() {
		mu.Unlock()
		return false
	}
	emit(WatchdogRequestSent)
	mu.Unlock()
	return true
}

type connWatchdog struct {
	conn            diam.Conn
	done            <-chan struct{}
	stop            <-chan struct{}
	signals         *watchdogSignals
	dwac            <-chan struct{}
	interval        func() time.Duration
	send            func() bool
	observe         func(WatchdogEvent)
	timeout         func() // accepted supervisors serialize terminal work with stop
	protocolTimeout func() // observes the committed timeout after existing close
}

type watchdogState struct {
	pending bool
	suspect bool
}

// The connection adapter retains its compact storage and owns no transitions.
// Managed peers retain DOWN/REOPEN across connections in their own control block.
func (s watchdogState) core() watchdog.Machine {
	state := watchdog.Okay
	if s.suspect {
		state = watchdog.Suspect
	}
	return watchdog.Machine{State: state, Pending: s.pending}
}

func (s *watchdogState) commit(next watchdog.Machine) {
	s.pending = next.Pending
	s.suspect = next.State == watchdog.Suspect
}

func (w *connWatchdog) receive(state *watchdogState, event watchdog.Event) {
	next, actions := state.core().Step(event)
	state.commit(next)
	if actions.Failback {
		w.observe(WatchdogRecovered)
	}
}

func (w *connWatchdog) run() {
	// RFC 3539 §3.4.1 and Appendix A: established peers start in OKAY.
	// Pending remains set after non-DWA traffic until the answer arrives.
	state := watchdogState{}
	for {
		window := watchdog.Reset(time.Now, w.interval)
		timer := time.NewTimer(window.After)
		select {
		case <-w.done:
			timer.Stop()
			return
		case <-w.stop:
			timer.Stop()
			return
		case <-w.signals.signal:
			timer.Stop()
			w.receive(&state, watchdog.Receive)
		case <-w.dwac:
			timer.Stop()
			w.receive(&state, watchdog.ReceiveDWA)
		case <-timer.C:
			if !w.expire(window.ArmedAt, &state) {
				return
			}
		}
	}
}

// expire handles the timer branch even when another select case is also ready.
// It reports whether the loop should arm a new timer.
func (w *connWatchdog) expire(armedAt time.Time, state *watchdogState) bool {
	// RFC 6733 §5.6: Closing excludes watchdog actions. The outer select
	// may choose the timer when stop is ready at the same instant.
	select {
	case <-w.stop:
		return false
	default:
	}
	// Prefer traffic delivered at the timer boundary to a false
	// expiration, including an answer already queued by its handler.
	if w.signals.last.Load() > armedAt.UnixNano() {
		w.receive(state, watchdog.Receive)
		return true
	}
	select {
	case <-w.dwac:
		w.receive(state, watchdog.ReceiveDWA)
		return true
	default:
	}
	next, actions := state.core().Step(watchdog.Expired)
	if actions.Close {
		// RFC 3539 Appendix A: a second Tw expiry in SUSPECT
		// transitions to DOWN and closes this connection.
		w.observe(WatchdogTimedOut)
		if w.timeout != nil {
			w.timeout()
		} else {
			logMessage(w.conn, nil, slog.LevelWarn, "sm: watchdog timeout; closing connection", nil)
			w.conn.Close()
			if w.protocolTimeout != nil {
				w.protocolTimeout()
			}
		}
		return false
	}
	if actions.Send && !w.send() {
		return false
	}
	state.commit(next)
	if actions.Failover {
		// StateMachine and Client have no peer queue; their supervisor observes
		// SUSPECT and owns any failover (RFC 3539 §3.4.1 [3]).
		w.observe(WatchdogSuspect)
	}
	return true
}
