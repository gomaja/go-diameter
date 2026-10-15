package sm

import (
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type closingConnection struct {
	mu       sync.Mutex
	closing  bool
	received bool
	timer    *time.Timer
	client   *watchdogActivity
}

func pendingRequests(c diam.Conn) *diam.PendingRequests {
	if tracker, ok := diam.ConnAs[interface{ PendingRequests() *diam.PendingRequests }](c); ok {
		return tracker.PendingRequests()
	}
	return nil
}

func (sm *StateMachine) closingConnection(c diam.Conn) *closingConnection {
	state := new(closingConnection)
	actual, loaded := sm.connections.LoadOrStore(c, state)
	if loaded {
		return actual.(*closingConnection)
	}
	// Each entry belongs to one native Conn generation. Retirement/closure
	// releases both its receiver timer and ownership (RFC 6733 §§5.5.4, 5.6).
	var done <-chan struct{}
	if _, native := diam.ConnAs[diam.ConnLifecycle](c); native {
		// EOF can publish CloseNotify before queued callbacks finish. Retain
		// admission through DispatchDone, including that half-close interval.
		done = connectionDone(c)
	} else if notifier, ok := diam.ConnAs[diam.CloseNotifier](c); ok {
		done = notifier.CloseNotify()
	}
	if done != nil {
		go func() {
			<-done
			state.mu.Lock()
			if state.timer != nil {
				state.timer.Stop()
			}
			state.mu.Unlock()
			sm.connections.CompareAndDelete(c, state)
		}()
	}
	return state
}

// enterClosing publishes the latch before DPR/DPA effects. Work admitted
// earlier retains its existing generation fencing (RFC 6733 §5.6).
func (sm *StateMachine) enterClosing(c diam.Conn) *closingConnection {
	state := sm.closingConnection(c)
	state.mu.Lock()
	client := state.client
	// Freeze ownership under the admission latch: a write registered after
	// Closing cannot acquire permission to dispatch its answer (§5.6).
	if requests := pendingRequests(c); requests != nil {
		requests.CloseAdmission()
	}
	if client != nil {
		client.latchStop()
	}
	if w := sm.supervised(c); w != nil {
		w.latchStop()
	}
	sm.markAcceptedClosing(c)
	state.closing = true
	state.mu.Unlock()
	return state
}

// joinClosingWatchdog preserves publication/observer ordering while the
// transport is live. RFC 6733 §5.6's deadline and transport closure take
// precedence over a writer or callback that does not return.
func (sm *StateMachine) joinClosingWatchdog(c diam.Conn, expired <-chan struct{}) bool {
	state := sm.closingConnection(c)
	state.mu.Lock()
	client := state.client
	state.mu.Unlock()
	w := sm.supervised(c)
	if client == nil && w == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		if client != nil {
			client.stopWatchdog()
		}
		if w != nil {
			w.stop()
		}
		close(done)
	}()
	var closed <-chan struct{}
	if notifier, ok := diam.ConnAs[diam.CloseNotifier](c); ok {
		closed = notifier.CloseNotify()
	}
	select {
	case <-done:
		return !c.Closed()
	case <-closed:
		// A read half-close also signals CloseNotify. Decoded callbacks may
		// still answer while the write side is live; they need not join it.
		return !c.Closed()
	case <-expired:
		return false
	}
}

func (sm *StateMachine) isClosing(c diam.Conn) bool {
	if state, ok := sm.connections.Load(c); ok {
		s := state.(*closingConnection)
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		return closing
	}
	return sm.acceptedClosing(c)
}

// closingAllowed runs before validation, activity and hooks. DPR/DPA retain
// their own validation/correlation. Other peer commands have no Closing event
// in RFC 6733 §5.6. Only answers owned by earlier application/session requests
// are admitted by the maintainer's draining policy.
func (sm *StateMachine) closingAllowed(c diam.Conn, m *diam.Message) bool {
	if !sm.isClosing(c) {
		return true
	}
	return sm.allowedWhileClosing(c, m)
}

func (sm *StateMachine) allowedWhileClosing(c diam.Conn, m *diam.Message) bool {
	if m == nil || m.Header == nil {
		return false
	}
	h := m.Header
	if h.ApplicationID == 0 {
		switch h.CommandCode {
		case diam.DisconnectPeer:
			return true
		case diam.CapabilitiesExchange, diam.DeviceWatchdog:
			return false
		}
	}
	if requests := pendingRequests(c); requests != nil {
		return requests.MatchAnswer(m, false)
	}
	return false
}

func completePendingAnswer(c diam.Conn, m *diam.Message) bool {
	if requests := pendingRequests(c); requests != nil {
		return requests.MatchAnswer(m, true)
	}
	return false
}
