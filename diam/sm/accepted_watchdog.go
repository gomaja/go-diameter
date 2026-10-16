package sm

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
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
		twinit = watchdog.DefaultTw
	}
	floor, jitter := cfg.watchdogTiming.parameters()
	// RFC 3539 §3.4.1 [1]: Twinit defaults to 30s and MUST NOT be below 6s.
	if twinit < floor {
		return nil, fmt.Errorf("watchdog interval %s is below RFC 3539 §3.4.1 minimum %s", twinit, floor)
	}
	return &watchdogPolicy{twinit: twinit, jitter: jitter, stream: cfg.WatchdogStream, onEvent: cfg.OnWatchdogConnEvent}, nil
}

// acceptedWatchdog serializes public watchdog observations and owns lifecycle
// teardown. Protocol state, correlation and all expiry decisions live in Core.
type acceptedWatchdog struct {
	state    *acceptedHandshake
	conn     diam.Conn
	mu       sync.Mutex
	closing  sync.WaitGroup
	stopped  atomic.Bool
	stopc    chan struct{}
	stopOnce sync.Once
	exited   chan struct{}
	policy   *watchdogPolicy
}

func (sm *StateMachine) registerAcceptedWatchdog(state *acceptedHandshake) {
	c := state.conn
	if state.policy == nil || c.Closed() || state.phase() != protocol.Open {
		return
	}
	var done <-chan struct{}
	if state.client != nil {
		done = clientConnectionDone(c)
	} else {
		done = connectionDone(c)
	}
	if done == nil {
		state.apply(protocol.Input{Kind: protocol.StopSupervision})
		text := "sm: watchdog disabled: connection exposes neither DispatchDone nor CloseNotifier"
		if state.client != nil {
			text = "sm: watchdog disabled: connection does not expose CloseNotifier"
		}
		logMessage(c, nil, slog.LevelWarn, text, nil)
		return
	}
	w := &acceptedWatchdog{state: state, conn: c, policy: state.policy, stopc: make(chan struct{}), exited: make(chan struct{})}
	state.mu.Lock()
	if state.watchdog != nil || state.core.Phase() != protocol.Open || c.Closed() {
		state.mu.Unlock()
		return
	}
	state.watchdog = w
	state.mu.Unlock()
	go func() {
		select {
		case <-done:
			if state.client != nil {
				state.apply(protocol.Input{Kind: protocol.StopSupervision})
			} else {
				state.apply(protocol.Input{Kind: protocol.TransportLost})
			}
		case <-w.stopc:
		}
		w.latchStop()
		w.mu.Lock()
		w.latchStop()
		w.mu.Unlock()
		w.closing.Wait()
		close(w.exited)
	}()
}
func (w *acceptedWatchdog) latchStop() {
	w.stopped.Store(true)
	w.stopOnce.Do(func() { close(w.stopc) })
}
func (w *acceptedWatchdog) stop() {
	w.state.apply(protocol.Input{Kind: protocol.StopSupervision})
	w.latchStop()
	w.mu.Lock()
	w.latchStop()
	w.mu.Unlock()
	w.closing.Wait()
}
func (w *acceptedWatchdog) observe(_ diam.Conn, event WatchdogEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.emit(event)
}
func (w *acceptedWatchdog) emit(event WatchdogEvent) {
	if w.stopped.Load() || w.conn.Closed() || w.policy.onEvent == nil {
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
