package protocol

import (
	"errors"
	"fmt"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func (c *Core) watchdogArm(es []Effect, at time.Time, interval time.Duration) []Effect {
	if interval <= 0 {
		interval = c.cfg.WatchdogInterval
	}
	if interval <= 0 {
		return c.stop(es, WatchdogTimer)
	}
	// RFC 3539 §3.4.1: stop the previous Tw before arming its replacement.
	previous := c.timers[WatchdogTimer]
	arm := c.effect(ArmTimer)
	arm.Timer, arm.Token, arm.Deadline = WatchdogTimer, c.token(), at.Add(interval)
	c.timers[WatchdogTimer] = TimerSnapshot{arm.Token, arm.Deadline}
	if previous.Token == 0 {
		return append(es, arm)
	}
	stop := c.effect(StopTimer)
	stop.Timer, stop.Token = WatchdogTimer, previous.Token
	return append(es, stop, arm)
}
func (c *Core) watchdogUp(es []Effect, in Input) []Effect {
	if !c.cfg.Watchdog {
		return es
	}
	next, actions := c.wd.Step(watchdog.ConnectionUp)
	c.wd = next
	if actions.Send {
		c.wdNext = &next
		c.wd.Pending = false
		return c.reserve(es, diam.DeviceWatchdog)
	}
	if actions.Reset {
		return c.watchdogArm(es, in.At, in.Interval)
	}
	return es
}
func (c *Core) watchdogPublished(es []Effect, in Input) []Effect {
	if c.phase != Open || c.wdNext == nil {
		return es
	}
	c.wd = *c.wdNext
	c.wdNext = nil
	es = c.watchdogArm(es, in.At, in.Interval)
	return append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: c.wd.State}))
}

// RFC 3539 §3.4.1 [2], Appendix A: any eligible decoded activity resets Tw;
// #108 withholds health credit from invalid traffic and Pending credit from
// everything except a validated, correlated, successful DWA.
func (c *Core) activity(es []Effect, in Input) []Effect {
	if c.phase != Open || !c.cfg.Watchdog || base.FatalHeaderError(in.Error) {
		return es
	}
	return c.watchdogArm(es, in.At, in.Interval)
}

func (c *Core) validActivity(es []Effect) []Effect {
	if c.phase != Open || !c.cfg.Watchdog {
		return es
	}
	next, actions := c.wd.Step(watchdog.Receive)
	c.wd = next
	if actions.Failback {
		return append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State}))
	}
	return es
}
func (c *Core) watchdogExpired(es []Effect, in Input) []Effect {
	if c.phase != Open || !c.cfg.Watchdog {
		return es
	}
	if in.AfterReceive > c.receivedSequence {
		saved := in
		c.deferredExpiry = &saved
		return es
	}
	// A selected probe is not Pending until publication. Activity may have
	// armed another Tw meanwhile; do not allocate a second probe or overwrite
	// the first reservation (RFC 3539 Appendix A, #108 publication boundary).
	if c.wdNext != nil {
		return c.watchdogArm(es, in.At, in.Interval)
	}
	next, actions := c.wd.Step(watchdog.Expired)
	if actions.Close {
		return c.fail(es, in, diam.ProtocolWatchdogTimeout, 0)
	}
	es = c.stop(es, WatchdogTimer)
	if actions.Send {
		c.wdNext = &next
		return c.reserve(es, diam.DeviceWatchdog)
	}
	c.wd = next
	if actions.Failover {
		es = append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State}))
	}
	if actions.Reset {
		es = c.watchdogArm(es, in.At, in.Interval)
	}
	return es
}
func (c *Core) dwa(es []Effect, in Input) []Effect {
	m := in.Message
	if err := base.ValidateMessage(m); err != nil {
		in.Error = err
		return c.discard(es, in, diam.ProtocolInvalidDWA, err.ResultCode)
	}
	// Grammar diagnostics precede ownership classification as library policy.
	// RFC 6733 §§3, 6.2.1: only a correlated answer owns the local exchange.
	if !c.matches(c.controls[diam.DeviceWatchdog], m) {
		es = c.discard(es, in, diam.ProtocolUnexpectedMessage, 0)
		es[len(es)-1].Notification.Diagnostic = "dwa-correlation"
		return es
	}
	var parsed base.DWA
	if err := parsed.Parse(m); err != nil {
		return c.discardCause(es, in, diam.ProtocolInvalidDWA, err)
	}
	r := c.controls[diam.DeviceWatchdog]
	if parsed.ResultCode != diam.Success && !c.bound(m, true) {
		var peer base.DWR
		_ = peer.Parse(m)
		err := errors.New("DWA Origin-Realm mismatch")
		if !equalIdentity(string(peer.OriginHost), c.caps.Host) {
			err = errors.New("DWA Origin-Host mismatch")
		}
		return c.discardCause(es, in, diam.ProtocolInvalidDWA, err)
	}
	if parsed.ResultCode != diam.Success {
		es = c.consumeControl(es, r, m)
		es = c.discard(es, in, diam.ProtocolRejectedDWA, parsed.ResultCode)
		es[len(es)-1].Notification.CauseError = fmt.Errorf("DWA Result-Code %d", parsed.ResultCode)
		return es
	}
	if !c.bound(m, true) || m.Header.CommandFlags&diam.ErrorFlag != 0 {
		var identity base.DWR
		err := identity.Parse(m)
		if err == nil {
			switch {
			case m.Header.CommandFlags&diam.ErrorFlag != 0:
				err = errors.New("invalid DWA flags")
			case !equalIdentity(string(identity.OriginHost), c.caps.Host):
				err = errors.New("DWA Origin-Host mismatch")
			default:
				err = errors.New("DWA Origin-Realm mismatch")
			}
		}
		return c.discardCause(es, in, diam.ProtocolInvalidDWA, err)
	}
	current := c.wd
	// A fast answer can precede the writer's return. Apply its credit to the
	// tentative send transition; the late completion cannot restore Pending.
	if c.wdNext != nil {
		current = *c.wdNext
		c.wdNext = nil
	}
	next, actions := current.Step(watchdog.ReceiveDWA)
	c.wd = next
	es = c.consumeControl(es, r, m)
	es = c.settle(es, r)
	es = append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State, Diagnostic: "answer"}))
	if actions.Failback {
		es = append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State}))
	}
	return es
}

func (c *Core) consumeControl(es []Effect, r *control, m *diam.Message) []Effect {
	if r.answered {
		return es
	}
	r.answered = true
	return append(es, c.consumed(m))
}

func (c *Core) consumed(m *diam.Message) Effect {
	e := c.effect(CompleteRequest)
	e.Notification.Message = metadata(m)
	return e
}
