package sm

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type watchdogPolicy struct {
	twinit  time.Duration
	jitter  time.Duration
	stream  uint
	onEvent func(diam.Conn, WatchdogEvent)
}

func acceptedWatchdogPolicy(cfg *Settings) (*watchdogPolicy, error) {
	if !cfg.EnableWatchdog {
		return nil, nil
	}
	twinit := cfg.WatchdogInterval
	if twinit == 0 {
		twinit = 30 * time.Second
	}
	floor, jitter := cfg.watchdogTiming.parameters()
	// RFC 3539 §3.4.1 [1]: Twinit defaults to 30s and MUST NOT be below 6s.
	if twinit < floor {
		return nil, fmt.Errorf("watchdog interval %s is below RFC 3539 §3.4.1 minimum %s", twinit, floor)
	}
	return &watchdogPolicy{twinit: twinit, jitter: jitter, stream: cfg.WatchdogStream, onEvent: cfg.OnWatchdogConnEvent}, nil
}

type acceptedWatchdog struct {
	connWatchdog
	signals  watchdogSignals
	mu       sync.Mutex
	closing  sync.WaitGroup // admitted terminal work completes before stop returns
	stopped  atomic.Bool
	stopc    chan struct{}
	stopOnce sync.Once
	exited   chan struct{}
	dwa      diam.Handler
	policy   *watchdogPolicy
}

func (sm *StateMachine) startWatchdog(c diam.Conn) {
	if sm.watchdog == nil || c.Closed() {
		return
	}
	done := connectionDone(c)
	if done == nil {
		logMessage(c, nil, slog.LevelWarn, "sm: watchdog disabled: connection exposes neither DispatchDone nor CloseNotifier", nil)
		return
	}
	w := &acceptedWatchdog{
		signals: newWatchdogSignals(), stopc: make(chan struct{}), exited: make(chan struct{}), policy: sm.watchdog,
	}
	w.connWatchdog = connWatchdog{
		conn: c, done: done, stop: w.stopc, signals: &w.signals, dwac: w.signals.dwac,
		interval: func() time.Duration { return jitteredTw(w.policy.twinit, w.policy.jitter) },
		send: func() bool {
			m, err := base.BuildDWR(c.Dictionary(), baseSettings(sm.cfg), uint32(sm.cfg.OriginStateID))
			if err != nil {
				w.terminate(nil, slog.LevelError, "sm: watchdog request failed; closing connection", err)
				return false
			}
			return publishDWR(c, m, w.policy.stream, &w.mu, &w.stopped, w.emit, func(err error) {
				w.terminate(m, slog.LevelError, "sm: watchdog request failed; closing connection", err)
			})
		},
		observe: func(event WatchdogEvent) { w.observe(c, event) },
		timeout: func() { w.terminate(nil, slog.LevelWarn, "sm: watchdog timeout; closing connection", nil) },
	}
	dwa := handleDWA(sm, w.signals.dwac, func(_ diam.Conn, event WatchdogEvent) { w.emit(event) })
	w.dwa = diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		w.mu.Lock()
		defer w.mu.Unlock()
		// RFC 6733 §5.6: Closing has no DWA event, even through a stale
		// supervisor pointer. Ignore it before parsing or crediting Pending.
		if w.stopped.Load() {
			return
		}
		dwa.ServeDIAM(c, m)
	})
	if _, loaded := sm.watchdogs.LoadOrStore(c, w); loaded {
		return
	}
	// RFC 6733 §5.6: Disconnect may enter Closing during the CEA write or
	// OnHandshake. It registers pending before stopping supervision, so the
	// later of this registration and Disconnect observes the other. If
	// Disconnect already removed pending, Closed retains that terminal state.
	sm.disconnects.mu.Lock()
	pending := sm.disconnects.pending[c] != nil
	sm.disconnects.mu.Unlock()
	if pending || c.Closed() {
		w.stop()
		sm.watchdogs.CompareAndDelete(c, w)
		close(w.exited)
		return
	}
	// RFC 3539 Appendix A: an initially admitted connection starts in OKAY.
	// RFC 6733 §2.1: reconnecting belongs to the connecting node, not this
	// responder; StateMachine keeps no per-peer control block for REOPEN.
	go func() {
		defer close(w.exited)
		defer sm.watchdogs.CompareAndDelete(c, w)
		defer w.stop()
		w.run()
	}()
}

func (sm *StateMachine) supervised(c diam.Conn) *acceptedWatchdog {
	if sm.watchdog == nil {
		return nil
	}
	w, ok := sm.watchdogs.Load(c)
	if !ok {
		return nil
	}
	return w.(*acceptedWatchdog)
}

func (sm *StateMachine) stopWatchdog(c diam.Conn) {
	w := sm.supervised(c)
	if w == nil {
		return
	}
	w.stop()
}

func (w *acceptedWatchdog) stop() {
	// RFC 6733 §5.6: Closing has no DWR/DWA events. Holding the publication
	// mutex guarantees no further DWR write, DWA credit or watchdog event.
	// Wait for terminal logging and Close before returning as well.
	w.mu.Lock()
	w.stopped.Store(true)
	w.stopOnce.Do(func() { close(w.stopc) })
	w.mu.Unlock()
	w.closing.Wait()
}

func (w *acceptedWatchdog) received() {
	// RFC 6733 §5.6: received traffic cannot restart a Closing watchdog.
	// Do not wait for a DWR write or callback before releasing admission.
	// A racing activity store is inert: the loop stops and events are gated.
	if w.stopped.Load() {
		return
	}
	w.signals.received()
}

func (w *acceptedWatchdog) terminate(m *diam.Message, level slog.Level, text string, err error) {
	// RFC 6733 §5.6: terminal watchdog work either completes before stop
	// returns or is suppressed. Leave the event mutex free during Close.
	w.mu.Lock()
	if w.stopped.Load() {
		w.mu.Unlock()
		return
	}
	// Add and stop's stopped.Store share mu: no terminal work can be
	// admitted after stop begins waiting, even when the count was zero.
	w.closing.Add(1)
	w.mu.Unlock()
	defer w.closing.Done()
	logMessage(w.conn, m, level, text, err)
	w.conn.Close()
}

func (w *acceptedWatchdog) observe(_ diam.Conn, event WatchdogEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.emit(event)
}

// emit runs with mu held, including when publishDWR publishes a request.
func (w *acceptedWatchdog) emit(event WatchdogEvent) {
	// RFC 6733 §5.6: serialize all events with stop, including a timer or
	// message handler already in flight when the connection enters Closing.
	if w.stopped.Load() || w.policy.onEvent == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			logMessage(w.conn, nil, slog.LevelError, "sm: watchdog event callback panicked; closing connection", fmt.Errorf("%v", p))
			w.conn.Close()
		}
	}()
	w.policy.onEvent(w.conn, event)
}
