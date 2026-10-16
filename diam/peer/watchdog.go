package peer

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// WatchdogState is the coupled connection health state from RFC 3539 Appendix A.
type WatchdogState string

const (
	WatchdogInitial WatchdogState = WatchdogState(watchdog.Initial)
	WatchdogOkay    WatchdogState = WatchdogState(watchdog.Okay)
	WatchdogSuspect WatchdogState = WatchdogState(watchdog.Suspect)
	WatchdogDown    WatchdogState = WatchdogState(watchdog.Down)
	WatchdogReopen  WatchdogState = WatchdogState(watchdog.Reopen)
)

type watchdogTiming struct{ floor, jitter time.Duration }

var errDWAResultCode = errors.New("peer: DWA Result-Code is not success")

// Preserve the failing top-level Result-Code (RFC 6733 §§5.5.2 and 7.1)
// without changing the watchdog decision or its diagnostic text.
type dwaResultCodeError struct{ result uint32 }

func (e *dwaResultCodeError) Error() string { return errDWAResultCode.Error() }
func (e *dwaResultCodeError) Unwrap() error { return errDWAResultCode }

func (a *actor) watchdogInterval() time.Duration {
	// RFC 3539 §3.4.1, Appendix A SetWatchdog: Twinit plus uniform ±2s.
	jitter := watchdog.DefaultJitter
	if a.m.cfg.watchdogTiming != nil {
		jitter = a.m.cfg.watchdogTiming.jitter
	}
	return watchdog.Tw(a.m.cfg.Timers.TwInit, jitter, rand.Int63n)
}

func (a *actor) stopWatchdog() {
	a.wdToken++
	a.deferredWatchdog = nil
	if a.wdTimer != nil {
		a.wdTimer.Stop()
		a.wdTimer = nil
	}
}
func (a *actor) stopReconnect() {
	a.tcToken++
	if a.tcTimer != nil {
		a.tcTimer.Stop()
		a.tcTimer = nil
	}
}
func (a *actor) reconnectInterval() time.Duration {
	base := a.m.cfg.Timers.Tc
	for i := 0; i < a.failures && base < 5*time.Minute; i++ {
		if base > 5*time.Minute/2 {
			base = 5 * time.Minute
			break
		}
		base *= 2
	}
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	// RFC 6733 §12 recommends 30s Tc. The backoff and ±20% jitter are local policy.
	factor := 0.8 + rand.Float64()*0.4
	d := time.Duration(float64(base) * factor)
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}
func (a *actor) scheduleReconnect() {
	if !a.leaseLive() || a.m.isClosing() || a.ownStop || a.suppressReconnect || a.cfg.NoAutoReconnect || len(a.cfg.Endpoints) == 0 || !a.m.hasStarted() {
		return
	}
	a.stopReconnect()
	d := a.reconnectInterval()
	if a.failures < 32 {
		a.failures++
	}
	token := a.tcToken
	a.tcTimer = a.m.cfg.Clock.AfterFunc(d, func() { a.post(event{kind: reconnectTimeout, token: token}) })
}
func (a *actor) reconnectTick() {
	// RFC 3539 Appendix A INITIAL/DOWN Timer expires: AttemptOpen. RFC 6733 §12
	// supplies Tc as the retry timer while there is no live connection.
	if !a.leaseLive() || a.state != Closed || a.m.isClosing() || a.ownStop || a.suppressReconnect || len(a.cfg.Endpoints) == 0 || !a.m.hasStarted() {
		return
	}
	if a.dialing {
		a.scheduleReconnect()
		return
	}
	a.setState(WaitConnAck, nil)
	a.arm(a.m.cfg.Timers.Connect)
	a.dial()
}
func (a *actor) changeWatchdog(next WatchdogState, reason error) {
	if a.watchdog == next {
		return
	}
	a.watchdog = next
	if reason == nil {
		reason = fmt.Errorf("peer: watchdog %s", next)
	}
	a.publish(reason)
	if next == WatchdogSuspect && a.active != nil {
		// RFC 3539 §3.4.1 and RFC 6733 §5.5.4: remove a SUSPECT
		// connection from new selection and fail over requests in flight.
		a.m.failoverSession(a.active)
	}
}

func (a *actor) lostConnection(reason error) {
	// An initial handshake can end with transport EOF rather than a rejected
	// CEA. Complete its acquisition acknowledgement before reconnect backoff.
	a.signalReady(reason)
	a.stopWatchdog()
	a.pendingWatchdog = false // release the dead transport's outstanding probe
	if a.everOpen {
		// Transport closure and session failover are already owned by the caller.
		a.changeWatchdog(WatchdogDown, reason)
	}
	a.scheduleReconnect()
}
