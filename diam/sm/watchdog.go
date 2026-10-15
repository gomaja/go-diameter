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
	publicationMu *sync.Mutex // dialed per-connection publication and credit
	stopped       atomic.Bool // dialed logical Closing; publication and credit are inert
	signal        chan struct{}
	last          atomic.Int64
	request       atomic.Pointer[diam.Header]
	mu            sync.Mutex
	activity      watchdogReceipt
	credit        watchdogReceipt
	validating    uint64
	publishedAt   time.Time
}

// RFC 3539 Appendix A permits one outstanding DWR. Retain only its credit
// and the newest activity; intermediate resets have no remaining effect.
// A validation token lives on the receiving handler's stack, not in a queue.
type watchdogReceipt struct {
	at                time.Time
	event             watchdog.Event
	healthy           bool
	pending           bool
	beforePublication bool
}

func newWatchdogSignals() watchdogSignals {
	return watchdogSignals{signal: make(chan struct{}, 1)}
}

func (s *watchdogSignals) received() {
	s.record(true)
}

func (s *watchdogSignals) receivedMessage(m *diam.Message) watchdogReceipt {
	// RFC 3539 §3.4.1, Appendix A: any decoded activity resets Tw, but
	// DWA restores health only after body and pending-request validation.
	return s.record(!isBaseDWA(m))
}

func (s *watchdogSignals) wake() {
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

func (s *watchdogSignals) record(healthy bool) watchdogReceipt {
	s.mu.Lock()
	r := watchdogReceipt{at: time.Now(), event: watchdog.Receive, healthy: healthy, pending: !healthy}
	s.last.Store(r.at.UnixNano())
	// Health recovery is sticky until consumed, even if a later invalid DWA
	// supplies the newest activity timestamp.
	s.activity = watchdogReceipt{at: r.at, event: watchdog.Receive, healthy: healthy || s.activity.healthy}
	if r.pending {
		s.validating++
	}
	s.mu.Unlock()
	s.wake()
	return r
}

func (s *watchdogSignals) finishDWA(r watchdogReceipt, credit bool) {
	s.mu.Lock()
	if r.pending {
		s.validating--
	}
	if credit {
		if r.at.IsZero() {
			// Direct DWA handlers also work without the activity adapter.
			r.at = time.Now()
		}
		s.credit = watchdogReceipt{at: r.at, event: watchdog.ReceiveDWA, healthy: true}
	}
	s.mu.Unlock()
	s.wake()
}

// nextDecision selects a receive or expiry event atomically. The caller samples
// time before taking the mutex: a stale sample can postpone expiry, but no
// answer admitted before that sample can be overtaken (RFC 3539 Appendix A).
func (s *watchdogSignals) nextDecision(window watchdog.Window, now time.Time) (r watchdogReceipt, waiting, expired bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// An admitted answer must finish its credit decision before expiry.
	if s.validating != 0 {
		return watchdogReceipt{}, true, false
	}
	if !s.credit.at.IsZero() && (s.activity.at.IsZero() || !s.credit.at.After(s.activity.at)) {
		r, s.credit = s.credit, watchdogReceipt{}
		if r.at.Equal(s.activity.at) {
			s.activity = watchdogReceipt{}
		}
		return r, false, false
	}
	r, s.activity = s.activity, watchdogReceipt{}
	return r, false, r.at.IsZero() && !now.Before(window.ArmedAt.Add(window.After))
}

func (s *watchdogSignals) published() {
	s.mu.Lock()
	s.publishedAt = time.Now()
	// Preserve receive/publication order even when clock readings tie.
	s.activity.beforePublication = true
	s.mu.Unlock()
}

func (s *watchdogSignals) publicationTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishedAt
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
	// RFC 3539 Appendix A: send, then reset Tw. Observer latency is not
	// part of publication and must not extend the peer's response window.
	signals.published()
	emit(WatchdogRequestSent)
	mu.Unlock()
	return true
}

type connWatchdog struct {
	conn            diam.Conn
	done            <-chan struct{}
	stop            <-chan struct{}
	signals         *watchdogSignals
	interval        func() time.Duration
	now             func() time.Time // nil uses the runtime clock
	send            func() bool
	observe         func(WatchdogEvent)
	timeout         func()    // accepted supervisors serialize terminal work with stop
	protocolTimeout func()    // observes the committed timeout after existing close
	resetAt         time.Time // loop-owned anchor committed by expire
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
	window := watchdog.Reset(time.Now, w.interval)
	waiting := false
	for {
		timer := time.NewTimer(time.Until(window.ArmedAt.Add(window.After)))
		tick := timer.C
		if waiting {
			timer.Stop()
			tick = nil
		}
		select {
		case <-w.done:
			timer.Stop()
			return
		case <-w.stop:
			timer.Stop()
			return
		case <-w.signals.signal:
		case <-tick:
		}
		timer.Stop()
		alive, pending := w.advance(&window, &state)
		if !alive {
			return
		}
		waiting = pending
	}
}

// advance arbitrates a timer and receive decisions using their receipt times.
// Waiting disables the timer until DWA validation completes; stop/done still win.
func (w *connWatchdog) advance(window *watchdog.Window, state *watchdogState) (alive, waiting bool) {
	// RFC 6733 §5.6: Closing excludes watchdog actions. The outer select
	// may choose the timer when stop is ready at the same instant.
	select {
	case <-w.done:
		return false, false
	case <-w.stop:
		return false, false
	default:
	}
	// RFC 3539 §3.4.1, Appendix A: commit each recorded receive, including
	// DWA credit, before considering the following expiry.
	for {
		r, waiting, expired := w.signals.nextDecision(*window, w.nowTime())
		if waiting {
			return true, true
		}
		if r.at.IsZero() {
			// Receipt emptiness and expiry were decided together under mu.
			// State belongs to this loop; writes and callbacks run unlocked.
			if expired {
				if !w.expire(state) {
					return false, false
				}
				*window = watchdog.Window{ArmedAt: w.resetAt, After: w.interval()}
			}
			return true, false
		}
		if r.healthy {
			w.receive(state, r.event)
		}
		armedAt := r.at
		// Activity received before a blocked DWR publishes cannot shorten its
		// new response window. A credited DWA proves receipt of that probe and
		// retains its own receipt time (RFC 3539 Appendix A OnReceive).
		if state.pending && r.event != watchdog.ReceiveDWA && r.beforePublication {
			continue
		}
		*window = watchdog.Window{ArmedAt: armedAt, After: w.interval()}
	}
}

func (w *connWatchdog) expire(state *watchdogState) bool {
	select {
	case <-w.stop:
		return false
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
	w.resetAt = time.Now()
	if actions.Send {
		if !w.send() {
			return false
		}
		// Production send records successful publication before notifying the
		// observer. Alternate senders without a publication stamp finish here.
		if published := w.signals.publicationTime(); !published.Before(w.resetAt) {
			w.resetAt = published
		} else {
			w.resetAt = time.Now()
		}
	}
	state.commit(next)
	if actions.Failover {
		// StateMachine and Client have no peer queue; their supervisor observes
		// SUSPECT and owns any failover (RFC 3539 §3.4.1 [3]).
		w.observe(WatchdogSuspect)
	}
	return true
}

func (w *connWatchdog) nowTime() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}
