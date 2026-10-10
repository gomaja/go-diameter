package sm

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type watchdogTiming struct {
	floor  time.Duration
	jitter time.Duration
}

func (t *watchdogTiming) parameters() (floor, jitter time.Duration) {
	if t != nil {
		return t.floor, t.jitter
	}
	return 6 * time.Second, 2 * time.Second
}

func jitteredTw(twinit, jitter time.Duration) time.Duration {
	if jitter == 0 {
		return twinit
	}
	// RFC 3539 §3.4.1 [1] and Appendix A SetWatchdog: redraw on every reset.
	return twinit - jitter + time.Duration(rand.Int63n(int64(2*jitter)+1))
}

type watchdogSignals struct {
	signal chan struct{}
	last   atomic.Int64
	dwac   chan struct{}
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

func publishDWR(c diam.Conn, m *diam.Message, stream uint, mu *sync.Mutex, stopped *atomic.Bool, emit func(WatchdogEvent), failed func(error)) bool {
	// RFC 6733 §5.6: entering Closing excludes further DWRs. Serialize the
	// check with the write and request event so a fast answer cannot overtake it.
	mu.Lock()
	if stopped != nil && stopped.Load() {
		mu.Unlock()
		return false
	}
	if _, err := m.WriteToStream(c, stream); err != nil {
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
	emit(WatchdogRequestSent)
	mu.Unlock()
	return true
}

type connWatchdog struct {
	conn     diam.Conn
	done     <-chan struct{}
	stop     <-chan struct{}
	signals  *watchdogSignals
	dwac     <-chan struct{}
	interval func() time.Duration
	send     func() bool
	observe  func(WatchdogEvent)
	timeout  func() // accepted supervisors serialize terminal work with stop
}

type watchdogState struct {
	pending bool
	suspect bool
}

func (w *connWatchdog) run() {
	// RFC 3539 §3.4.1 and Appendix A: established peers start in OKAY.
	// Pending remains set after non-DWA traffic until the answer arrives.
	state := watchdogState{}
	for {
		armedAt := time.Now()
		timer := time.NewTimer(w.interval())
		select {
		case <-w.done:
			timer.Stop()
			return
		case <-w.stop:
			timer.Stop()
			return
		case <-w.signals.signal:
			timer.Stop()
			if state.suspect {
				state.suspect = false
				w.observe(WatchdogRecovered)
			}
		case <-w.dwac:
			timer.Stop()
			state.pending = false
			if state.suspect {
				state.suspect = false
				w.observe(WatchdogRecovered)
			}
		case <-timer.C:
			if !w.expire(armedAt, &state) {
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
		if state.suspect {
			state.suspect = false
			w.observe(WatchdogRecovered)
		}
		return true
	}
	select {
	case <-w.dwac:
		state.pending = false
		if state.suspect {
			state.suspect = false
			w.observe(WatchdogRecovered)
		}
		return true
	default:
	}
	if state.suspect {
		// RFC 3539 Appendix A: a second Tw expiry in SUSPECT
		// transitions to DOWN and closes this connection.
		w.observe(WatchdogTimedOut)
		if w.timeout != nil {
			w.timeout()
		} else {
			logMessage(w.conn, nil, slog.LevelWarn, "sm: watchdog timeout; closing connection", nil)
			w.conn.Close()
		}
		return false
	}
	if state.pending {
		// RFC 3539 Appendix A: failover belongs to the caller's
		// supervisor; StateMachine and Client have no peer queue.
		state.suspect = true
		w.observe(WatchdogSuspect)
		return true
	}
	if !w.send() {
		return false
	}
	state.pending = true
	return true
}
