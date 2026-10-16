package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func acceptedTestSupervisor(sm *StateMachine, c diam.Conn) (*acceptedWatchdog, bool) {
	state := sm.acceptedCore(c, nil, false)
	if state == nil || state.client != nil {
		return nil, false
	}
	w := state.watchdogState()
	return w, w != nil && !w.stopped.Load()
}

func stopAcceptedTestWatchdog(sm *StateMachine, c diam.Conn) {
	if state := sm.acceptedCore(c, nil, false); state != nil {
		if w := state.watchdogState(); w != nil {
			w.stop()
		}
	}
}

func savedApplicationOfferSupports(c diam.Conn, app uint32) bool {
	local, _ := c.Context().Value(advertisedAppsKey{}).([]uint32)
	return base.SupportsApplication(local, app)
}

// Private supervisor tests start after capability exchange. Drive the real
// responder transitions, but leave CEA I/O and public handshake hooks to the
// handshake integration tests.
func primeAcceptedTestCore(t *testing.T, sm *StateMachine, c diam.Conn) *acceptedHandshake {
	t.Helper()
	state := sm.acceptedCore(c, nil, true)
	if state == nil {
		return nil
	}
	snap := state.snapshot()
	if snap.Phase() != protocol.PreCER {
		return state
	}
	request := regressionCER(t, sm.capabilityDictionary(c, nil), 1001)
	batch := state.prepare(protocol.Input{Kind: protocol.Receive, Message: request})
	for _, e := range batch.effects {
		if e.Kind == protocol.RunHook {
			batch = state.prepare(protocol.Input{Kind: protocol.Continue, Token: e.Token, Message: e.Message})
			break
		}
	}
	var sent protocol.Effect
	for _, e := range batch.effects {
		switch e.Kind {
		case protocol.Publish:
			state.run(acceptedBatch{effects: []protocol.Effect{e}})
		case protocol.Send:
			sent = e
		}
	}
	if sent.Token == 0 {
		t.Fatalf("capability setup did not select CEA: phase=%v effects=%v", state.snapshot().Phase(), batch.effects)
	}
	batch = state.prepare(protocol.Input{Kind: protocol.WriteResult, Token: sent.Token, Stage: protocol.WrittenStage, Bytes: int64(sent.Message.Len()), ExpectedBytes: int64(sent.Message.Len())})
	var admission uint64
	for _, e := range batch.effects {
		if e.Kind == protocol.HandshakeReady {
			admission = e.Token
		}
	}
	if admission == 0 {
		t.Fatal("capability setup did not complete CEA")
	}
	t.Cleanup(func() {
		state.mu.Lock()
		defer state.mu.Unlock()
		for _, timer := range state.timers {
			if timer != nil {
				timer.Stop()
			}
		}
	})
	return state
}

func startAcceptedTestWatchdog(t *testing.T, sm *StateMachine, c diam.Conn) {
	t.Helper()
	state := primeAcceptedTestCore(t, sm, c)
	if state == nil {
		return
	}
	sm.registerAcceptedWatchdog(state)
	snap := state.snapshot()
	if snap.Phase() == protocol.Open && !snap.Ready() {
		state.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: snap.Admission()})
	}
}

func receiveAcceptedTestWatchdog(w *acceptedWatchdog, m *diam.Message) {
	w.state.apply(protocol.Input{Kind: protocol.Receive, Message: m})
}

func expireAcceptedTestWatchdog(w *acceptedWatchdog) bool {
	timer := w.state.snapshot().Timer(protocol.WatchdogTimer)
	w.state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer, Token: timer.Token, At: timer.Deadline})
	return !w.conn.Closed() && w.state.snapshot().Phase() == protocol.Open
}

func timeoutAcceptedTestWatchdog(w *acceptedWatchdog) {
	for range 3 {
		if !expireAcceptedTestWatchdog(w) {
			return
		}
	}
}

func expireAcceptedTestHandshake(state *acceptedHandshake) {
	timer := state.snapshot().Timer(protocol.HandshakeTimer)
	state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.HandshakeTimer, Token: timer.Token, At: timer.Deadline})
}

// Preserve AcceptHandler discovery while a client test substitutes the remote
// endpoint's DWR behavior at the transport dispatch boundary.
type acceptedDWRTestHandler struct {
	*StateMachine
	dwr diam.HandlerFunc
}

func (h acceptedDWRTestHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == diam.DeviceWatchdog && m.Header.CommandFlags&diam.RequestFlag != 0 {
		h.dwr(c, m)
		return
	}
	h.StateMachine.ServeDIAM(c, m)
}
