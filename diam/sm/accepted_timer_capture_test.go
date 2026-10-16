package sm

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestPreparedTimerCallbackAllocationsAreBounded(t *testing.T) {
	state := &acceptedHandshake{}
	var effects [3]protocol.Effect
	allocations := testing.AllocsPerRun(100, func() {
		effects = [3]protocol.Effect{
			{Kind: protocol.StopTimer, Timer: protocol.HandshakeTimer},
			{Kind: protocol.ArmTimer, Timer: protocol.HandshakeTimer, Token: 7, Deadline: time.Now().Add(time.Hour)},
			{Kind: protocol.Discard},
		}
		release := false
		state.prepareLocked(effects[:], &release)
		state.timer.Stop()
	})
	// A replacement needs its runtime timer and scalar callback. Consuming
	// bookkeeping must not retain separate copies of the batch's large effects.
	if allocations > 2 {
		t.Fatalf("timer callback preparation allocates %.0f objects; want at most two", allocations)
	}
}

func TestHandshakeTimerCallbackOwnsSelectedCoordinates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newSMTestDictionary(dict.Base())
		cfg := testMessageErrorSettings(d)
		cfg.HandshakeTimeout = time.Second
		sm := mustNewStateMachine(t, cfg, d)
		c := newHandshakeConn()
		state := sm.acceptedCore(c, nil, true)
		defer state.apply(protocol.Input{Kind: protocol.Abort})
		timer := state.snapshot().Timer(protocol.HandshakeTimer)
		effects := []protocol.Effect{
			{Kind: protocol.ArmTimer, Timer: protocol.HandshakeTimer, Token: timer.Token, Deadline: timer.Deadline},
			{Kind: protocol.Discard, Timer: protocol.WatchdogTimer, Token: timer.Token + 100},
		}
		state.mu.Lock()
		release := false
		prepared := state.prepareLocked(effects, &release)
		alias := state.timer == state.timers[protocol.HandshakeTimer]
		state.mu.Unlock()
		if !alias || len(prepared) != 1 || prepared[0].Kind != protocol.Discard {
			t.Fatalf("handshake timer alias=%t prepared=%+v", alias, prepared)
		}
		// The batch owns this storage and may overwrite it after preparation.
		clear(effects)
		time.Sleep(time.Second)
		synctest.Wait()
		if !c.Closed() || state.phase() != protocol.Closed {
			t.Fatal("actual handshake callback lost its selected timer kind or token")
		}
	})
}

func TestWatchdogTimerCallbackRetainsStaleToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		cfg.HandshakeTimeout = -1
		sm := mustNewStateMachine(t, &cfg)
		c := newAcceptedWatchdogProbeConn()
		defer close(c.done)
		startAcceptedTestWatchdog(t, sm, c)
		state := sm.acceptedCore(c, nil, false)
		defer state.apply(protocol.Input{Kind: protocol.Abort})
		before := state.snapshot().Timer(protocol.WatchdogTimer)
		state.mu.Lock()
		physical := state.timers[protocol.WatchdogTimer]
		// Replace logical ownership at the same deadline without executing its
		// Stop/Arm effects: the real older callback must keep its old token.
		state.core.Handle(protocol.Input{Kind: protocol.Receive, Connection: state.id, Message: diam.NewRequest(diam.ReAuth, 1001, c.Dictionary()), At: time.Now(), Interval: time.Until(before.Deadline)})
		after := state.core.Snapshot().Timer(protocol.WatchdogTimer)
		state.mu.Unlock()
		if physical == nil || before.Token == 0 || before.Token == after.Token || !before.Deadline.Equal(after.Deadline) {
			t.Fatalf("watchdog replacement before=%+v after=%+v timer=%p", before, after, physical)
		}
		time.Sleep(time.Until(before.Deadline))
		synctest.Wait()
		snapshot := state.snapshot()
		if physical.Stop() || snapshot.Timer(protocol.WatchdogTimer) != after || len(snapshot.Controls()) != 0 || c.Closed() || len(c.writes) != 0 {
			t.Fatalf("actual stale callback changed live watchdog: timer=%+v controls=%+v writes=%d closed=%t", snapshot.Timer(protocol.WatchdogTimer), snapshot.Controls(), len(c.writes), c.Closed())
		}
	})
}
