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
)

// WatchdogState is the coupled connection health state from RFC 3539 Appendix A.
type WatchdogState string

const (
	WatchdogInitial WatchdogState = "INITIAL"
	WatchdogOkay    WatchdogState = "OKAY"
	WatchdogSuspect WatchdogState = "SUSPECT"
	WatchdogDown    WatchdogState = "DOWN"
	WatchdogReopen  WatchdogState = "REOPEN"
)

type watchdogTiming struct{ floor, jitter time.Duration }

func (a *actor) watchdogInterval() time.Duration {
	// RFC 3539 §3.4.1, Appendix A SetWatchdog: Twinit plus uniform ±2s.
	jitter := 2 * time.Second
	if a.m.cfg.watchdogTiming != nil {
		jitter = a.m.cfg.watchdogTiming.jitter
	}
	if jitter == 0 {
		return a.m.cfg.Timers.TwInit
	}
	return a.m.cfg.Timers.TwInit - jitter + time.Duration(rand.Int63n(int64(2*jitter)+1))
}

func (a *actor) stopWatchdog() {
	a.wdToken++
	if a.wdTimer != nil {
		a.wdTimer.Stop()
		a.wdTimer = nil
	}
}
func (a *actor) armWatchdog() {
	a.stopWatchdog()
	token := a.wdToken
	gen := uint64(0)
	if a.active != nil {
		gen = a.active.gen
	}
	a.wdTimer = a.m.cfg.Clock.AfterFunc(a.watchdogInterval(), func() { a.post(event{kind: watchdogTimeout, token: token, gen: gen}) })
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
	if a.m.isClosing() || a.ownStop || a.suppressReconnect || a.cfg.NoAutoReconnect || len(a.cfg.Endpoints) == 0 || !a.m.hasStarted() {
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
	if a.state != Closed || a.m.isClosing() || a.ownStop || a.suppressReconnect || len(a.cfg.Endpoints) == 0 || !a.m.hasStarted() {
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
}
func (a *actor) onOpen() {
	// RFC 3539 Appendix A INITIAL/DOWN Connection up rows.
	a.stopReconnect()
	if a.watchdog == WatchdogDown {
		a.numDWA = 0
		a.changeWatchdog(WatchdogReopen, errors.New("peer: recovered connection awaiting three DWA"))
		a.sendWatchdog()
	} else {
		a.changeWatchdog(WatchdogOkay, errors.New("peer: initial connection established"))
		a.failures = 0
	}
	a.everOpen = true
	if a.state == IOpen || a.state == ROpen {
		a.armWatchdog()
	}
}
func (a *actor) lostConnection(reason error) {
	a.stopWatchdog()
	a.pendingWatchdog = false
	if a.everOpen {
		// RFC 3539 Appendix A OKAY/SUSPECT/REOPEN Connection down. Pending
		// request failover attaches here when PR 4 adds managed requests.
		a.changeWatchdog(WatchdogDown, reason)
	}
	a.scheduleReconnect()
}
func (a *actor) sendWatchdog() {
	if a.active == nil {
		return
	}
	msg, err := base.BuildDWR(a.m.dictionary(), a.m.baseSettings(a.active.c), uint32(a.m.cfg.Settings.OriginStateID))
	if err != nil {
		a.fail(fmt.Errorf("peer: build DWR: %w", err))
		return
	}
	if !a.active.send(msg, false) {
		a.fail(errors.New("peer: DWR write queue full"))
		return
	}
	a.pendingWatchdog = true
	a.watchdogHop = msg.Header.HopByHopID
	a.watchdogEnd = msg.Header.EndToEndID
	a.watchdogGen = a.active.gen
}
func (a *actor) watchdogTick() {
	// RFC 3539 Appendix A timer rows. No DWR is retransmitted while pending.
	switch a.watchdog {
	case WatchdogInitial, WatchdogDown:
		a.reconnectTick()
	case WatchdogOkay:
		if !a.pendingWatchdog {
			a.sendWatchdog()
		} else {
			a.changeWatchdog(WatchdogSuspect, errors.New("peer: unanswered DWR; pending request failover reserved for PR 4"))
		}
		if a.watchdog == WatchdogOkay || a.watchdog == WatchdogSuspect {
			a.armWatchdog()
		}
	case WatchdogSuspect:
		a.fail(errors.New("peer: watchdog suspect timeout"))
	case WatchdogReopen:
		if !a.pendingWatchdog {
			a.sendWatchdog()
			if a.watchdog == WatchdogReopen {
				a.armWatchdog()
			}
			return
		}
		if a.numDWA < 0 {
			a.fail(errors.New("peer: recovery DWR unanswered"))
			return
		}
		a.numDWA = -1
		a.armWatchdog()
	}
}
func (a *actor) watchdogReceive(msg *diam.Message) bool {
	// RFC 3539 Appendix A OnReceive resets Tw in OKAY/SUSPECT. REOPEN
	// discards non-DWA traffic and keeps its probe timer running, otherwise
	// an active remote watchdog can prevent the three recovery probes.
	if a.watchdog == WatchdogOkay || a.watchdog == WatchdogSuspect {
		a.armWatchdog()
	}
	if msg.Header.CommandCode != diam.DeviceWatchdog || msg.Header.CommandFlags&diam.RequestFlag != 0 {
		if a.watchdog == WatchdogSuspect {
			a.changeWatchdog(WatchdogOkay, errors.New("peer: traffic restored watchdog health"))
			a.failures = 0
		}
		return true
	}
	if msg.Header.ApplicationID != 0 {
		a.m.report(a.active, msg, errors.New("peer: DWA application ID is not zero"))
		return false
	}
	if !a.pendingWatchdog || a.active == nil || a.watchdogGen != a.active.gen || msg.Header.HopByHopID != a.watchdogHop || msg.Header.EndToEndID != a.watchdogEnd {
		a.m.report(a.active, msg, errors.New("peer: unsolicited or mismatched DWA"))
		return false
	}
	if err := a.validateDWA(msg); err != nil {
		a.m.report(a.active, msg, err)
		return false
	}
	a.pendingWatchdog = false
	switch a.watchdog {
	case WatchdogSuspect:
		a.changeWatchdog(WatchdogOkay, errors.New("peer: valid DWA restored watchdog health"))
		a.failures = 0
	case WatchdogReopen:
		a.numDWA++
		if a.numDWA == 3 {
			a.changeWatchdog(WatchdogOkay, errors.New("peer: three valid recovery DWA"))
			a.failures = 0
		}
	}
	return true
}

func (a *actor) validateDWA(msg *diam.Message) error {
	// RFC 6733 §5.5.2: one success Result-Code and one identity pair.
	if msg.Header.CommandFlags != 0 {
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
			if !ok || uint32(value) != diam.Success {
				return errors.New("peer: DWA Result-Code is not success")
			}
		}
	}
	if hosts != 1 || realms != 1 || results != 1 {
		return errors.New("peer: DWA requires one Result-Code, Origin-Host and Origin-Realm")
	}
	return nil
}
