package peer

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
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
func (a *actor) armWatchdog() {
	a.armWatchdogAt(a.m.now())
}

func (a *actor) armWatchdogAt(receivedAt time.Time) {
	a.stopWatchdog()
	token := a.wdToken
	gen := uint64(0)
	if a.active != nil {
		gen = a.active.gen
	}
	s := a.active
	// RFC 3539 §3.4.1 and Appendix A SetWatchdog: Tw starts at receipt,
	// not after ingress/actor backlog. An overdue reset fires immediately.
	delay := max(time.Duration(0), receivedAt.Add(a.watchdogInterval()).Sub(a.m.now()))
	a.wdTimer = a.m.cfg.Clock.AfterFunc(delay, func() {
		barrier := uint64(0)
		if s != nil {
			barrier = s.receiveBarrier()
		}
		a.post(event{kind: watchdogTimeout, token: token, gen: gen, s: s, afterReceive: barrier})
	})
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

// watchdogCore is caller-owned storage; only the shared Step defines transitions.
func (a *actor) watchdogCore() watchdog.Machine {
	return watchdog.Machine{State: watchdog.State(a.watchdog), Pending: a.pendingWatchdog, NumDWA: a.numDWA}
}

func (a *actor) onOpen() {
	// RFC 3539 Appendix A INITIAL/DOWN Connection up rows.
	a.stopReconnect()
	current := a.watchdogCore()
	// A new admitted transport with no DOWN history is initial admission.
	if current.State != watchdog.Down {
		current.State = watchdog.Initial
	}
	next, actions := current.Step(watchdog.ConnectionUp)
	a.numDWA = next.NumDWA
	if actions.Send {
		a.changeWatchdog(WatchdogState(next.State), errors.New("peer: recovered connection awaiting three DWA"))
		a.sendWatchdog()
	} else {
		a.pendingWatchdog = next.Pending
		a.changeWatchdog(WatchdogState(next.State), errors.New("peer: initial connection established"))
		a.failures = 0
	}
	a.everOpen = true
	if a.state == IOpen || a.state == ROpen {
		a.armWatchdog()
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
		next, _ := a.watchdogCore().Step(watchdog.ConnectionDown)
		a.changeWatchdog(WatchdogState(next.State), reason)
	}
	a.scheduleReconnect()
}
func (a *actor) sendWatchdog() {
	if a.active == nil {
		return
	}
	msg, err := base.BuildDWR(a.m.dictionary(), a.m.baseSettings(a.active.c), uint32(a.m.cfg.Settings.OriginStateID))
	if err != nil {
		a.failLocal("build DWR", err)
		return
	}
	if err := a.active.sendControl(msg); err != nil {
		a.failLocal("send DWR", err)
		return
	}
	a.pendingWatchdog = true
	a.watchdogAnswered = false
	a.watchdogHop = msg.Header.HopByHopID
	a.watchdogEnd = msg.Header.EndToEndID
	a.watchdogGen = a.active.gen
}
func (a *actor) watchdogTick() {
	next, actions := a.watchdogCore().Step(watchdog.Expired)
	a.numDWA = next.NumDWA
	if actions.Open {
		// Disconnected peers use the caller's Tc/backoff policy, not a live Tw.
		a.reconnectTick()
		return
	}
	if actions.Close {
		reason := errors.New("peer: watchdog suspect timeout")
		if a.watchdog == WatchdogReopen {
			reason = errors.New("peer: recovery DWR unanswered")
		}
		connection := a.active
		// fail owns close, Pending cleanup and DOWN publication. Do not publish
		// the candidate before its transport lifecycle actions have completed.
		a.fail(reason)
		if connection != nil {
			a.protocolError(connection.c, nil, diam.ProtocolWatchdogTimeout, 0, true, diam.ProtocolReplyNone, 0)
		}
		return
	}
	if actions.Failover {
		a.changeWatchdog(WatchdogState(next.State), errors.New("peer: unanswered DWR"))
	}
	if actions.Send {
		a.sendWatchdog()
	}
	// A synchronous build/queue failure can move the actor to DOWN. Never
	// overwrite it with the candidate or rearm a timer for the dead transport.
	if actions.Reset && a.watchdog == WatchdogState(next.State) {
		a.armWatchdog()
	}
}
func (a *actor) watchdogReceive(msg *diam.Message) bool {
	return a.watchdogReceiveAt(msg, a.m.now())
}

func (a *actor) watchdogReceiveAt(msg *diam.Message, receivedAt time.Time) bool {
	if receivedAt.IsZero() {
		receivedAt = a.m.now()
	}
	event := watchdog.Receive
	isDWA := msg.Header.CommandCode == diam.DeviceWatchdog && msg.Header.CommandFlags&diam.RequestFlag == 0
	if isDWA {
		event = watchdog.ReceiveDWA
	}
	next, actions := a.watchdogCore().Step(event)
	// Preserve receive ordering: OKAY/SUSPECT activity resets Tw even if a DWA
	// is subsequently rejected. Commit its state changes only after validation.
	// RFC 3539 Appendix A REOPEN receives do not postpone recovery probes.
	if actions.Reset {
		a.armWatchdogAt(receivedAt)
	}
	if !isDWA {
		if actions.Failback {
			a.changeWatchdog(WatchdogState(next.State), errors.New("peer: traffic restored watchdog health"))
			a.failures = 0
		}
		return true
	}
	if msg.Header.ApplicationID != 0 {
		a.m.report(a.active, msg, errors.New("peer: DWA application ID is not zero"))
		a.protocolError(a.active.c, msg, diam.ProtocolInvalidDWA, 0, false, diam.ProtocolReplyNone, 0)
		return false
	}
	if err := base.ValidateMessage(msg); err != nil {
		a.m.rejectBaseMessage(a.active, msg, err, false, false, a.delivery)
		return false
	}
	if !a.pendingWatchdog || a.active == nil || a.watchdogGen != a.active.gen || msg.Header.HopByHopID != a.watchdogHop || msg.Header.EndToEndID != a.watchdogEnd {
		a.m.report(a.active, msg, errors.New("peer: unsolicited or mismatched DWA"))
		if a.active != nil {
			a.protocolError(a.active.c, msg, diam.ProtocolInvalidDWA, 0, false, diam.ProtocolReplyNone, 0)
		}
		return false
	}
	if err := a.validateDWA(msg); err != nil {
		// RFC 6733 §5.4: a structurally valid, correlated unsuccessful
		// DWA is an answer to in-flight work, without granting the existing
		// RFC 3539 probe credit or changing Pending/recovery policy.
		if errors.Is(err, errDWAResultCode) && a.validateDWAResponse(msg, false) == nil {
			a.watchdogAnswered = true
			if a.active.requests != nil {
				a.active.requests.MatchAnswer(msg, true)
			}
		}
		a.m.report(a.active, msg, err)
		if a.m.cfg.Settings.OnProtocolError != nil {
			kind, result := diam.ProtocolInvalidDWA, uint32(0)
			if code := protocolResultCode(err); errors.Is(err, errDWAResultCode) && code != 0 && code != diam.Success {
				kind, result = diam.ProtocolRejectedDWA, code
			}
			a.protocolError(a.active.c, msg, kind, result, false, diam.ProtocolReplyNone, 0)
		}
		return false
	}
	a.watchdogAnswered = true
	if a.active.requests != nil {
		a.active.requests.MatchAnswer(msg, true)
	}
	a.pendingWatchdog = next.Pending
	a.active.releaseControl(a.watchdogHop)
	a.numDWA = next.NumDWA
	if actions.Failback {
		reason := errors.New("peer: valid DWA restored watchdog health")
		if a.watchdog == WatchdogReopen {
			reason = errors.New("peer: three valid recovery DWA")
		}
		a.changeWatchdog(WatchdogState(next.State), reason)
		a.failures = 0
	}
	return true
}

func (a *actor) validateDWA(msg *diam.Message) error {
	return a.validateDWAResponse(msg, true)
}

// validateDWAResponse preserves successful-probe validation and optionally
// checks response structure alone for the Closing in-flight indication.
func (a *actor) validateDWAResponse(msg *diam.Message, successOnly bool) error {
	// RFC 6733 §5.5.2: one success Result-Code and one identity pair.
	// RFC 6733 §3: receivers ignore reserved bits; the defined command
	// flags must still be clear in a successful DWA.
	flags := msg.Header.CommandFlags
	if flags&(diam.RequestFlag|diam.RetransmittedFlag) != 0 || flags&diam.ProxiableFlag != 0 && flags&diam.ErrorFlag == 0 {
		return errors.New("peer: invalid DWA flags")
	}
	var hosts, realms, results int
	for _, field := range msg.AVP {
		if field.VendorID != 0 {
			continue
		}
		switch field.Code {
		case avp.OriginHost:
			hosts++
			value, ok := field.Data.(datatype.DiameterIdentity)
			if !ok || compareIdentity(value, a.cfg.Host) != 0 {
				return errors.New("peer: DWA Origin-Host mismatch")
			}
		case avp.OriginRealm:
			realms++
			value, ok := field.Data.(datatype.DiameterIdentity)
			if !ok || len(value) == 0 || a.meta != nil && compareIdentity(value, a.meta.OriginRealm) != 0 {
				return errors.New("peer: DWA Origin-Realm mismatch")
			}
		case avp.ResultCode:
			results++
			value, ok := field.Data.(datatype.Unsigned32)
			if !ok || successOnly && uint32(value) != diam.Success {
				if a.m.cfg.Settings.OnProtocolError == nil {
					return errDWAResultCode
				}
				return &dwaResultCodeError{result: uint32(value)}
			}
		}
	}
	if hosts != 1 || realms != 1 || results != 1 {
		return errors.New("peer: DWA requires one Result-Code, Origin-Host and Origin-Realm")
	}
	if successOnly && msg.Header.CommandFlags&diam.ErrorFlag != 0 {
		return errors.New("peer: invalid successful DWA flags")
	}
	return nil
}
