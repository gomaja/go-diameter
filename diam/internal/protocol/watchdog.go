package protocol

import (
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func (c *Core) watchdogArm(at time.Time, interval time.Duration) []Effect {
	if interval <= 0 {
		interval = c.cfg.WatchdogInterval
	}
	es := c.stop(WatchdogTimer)
	return append(es, c.arm(WatchdogTimer, at, interval)...)
}
func (c *Core) watchdogUp(in Input) []Effect {
	if !c.cfg.Watchdog {
		return nil
	}
	next, actions := c.wd.Step(watchdog.ConnectionUp)
	c.wd = next
	if actions.Send {
		c.wdNext = &next
		c.wd.Pending = false
		return c.reserve(diam.DeviceWatchdog)
	}
	if actions.Reset {
		return c.watchdogArm(in.At, in.Interval)
	}
	return nil
}
func (c *Core) watchdogPublished(in Input) []Effect {
	if c.phase != Open || c.wdNext == nil {
		return nil
	}
	c.wd = *c.wdNext
	c.wdNext = nil
	es := c.watchdogArm(in.At, in.Interval)
	return append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: c.wd.State}))
}

// RFC 3539 §3.4.1 [2], Appendix A: any eligible decoded activity resets Tw;
// #108 withholds health credit from invalid traffic and Pending credit from
// everything except a validated, correlated, successful DWA.
func (c *Core) activity(in Input) []Effect {
	if c.phase != Open || !c.cfg.Watchdog || base.FatalHeaderError(in.Error) {
		return nil
	}
	return c.watchdogArm(in.At, in.Interval)
}

func (c *Core) validActivity() []Effect {
	if c.phase != Open || !c.cfg.Watchdog {
		return nil
	}
	next, actions := c.wd.Step(watchdog.Receive)
	c.wd = next
	if actions.Failback {
		return []Effect{c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State})}
	}
	return nil
}
func (c *Core) watchdogExpired(in Input) []Effect {
	if c.phase != Open || !c.cfg.Watchdog {
		return nil
	}
	if in.AfterReceive > c.receivedSequence {
		saved := in
		c.deferredExpiry = &saved
		return nil
	}
	// A selected probe is not Pending until publication. Activity may have
	// armed another Tw meanwhile; do not allocate a second probe or overwrite
	// the first reservation (RFC 3539 Appendix A, #108 publication boundary).
	if c.wdNext != nil {
		return c.watchdogArm(in.At, in.Interval)
	}
	next, actions := c.wd.Step(watchdog.Expired)
	if actions.Close {
		return c.fail(in, diam.ProtocolWatchdogTimeout, 0)
	}
	es := c.stop(WatchdogTimer)
	if actions.Send {
		c.wdNext = &next
		return append(es, c.reserve(diam.DeviceWatchdog)...)
	}
	c.wd = next
	if actions.Failover {
		es = append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State}))
	}
	if actions.Reset {
		es = append(es, c.watchdogArm(in.At, in.Interval)...)
	}
	return es
}
func (c *Core) dwa(in Input) []Effect {
	m := in.Message
	if err := base.ValidateMessage(m); err != nil {
		return c.discard(in, diam.ProtocolInvalidDWA, err.ResultCode)
	}
	r := c.controls[diam.DeviceWatchdog]
	if !c.matches(r, m) || !c.bound(m, true) {
		return c.discard(in, diam.ProtocolInvalidDWA, 0)
	}
	var parsed base.DWA
	if parsed.Parse(m) != nil {
		return c.discard(in, diam.ProtocolInvalidDWA, 0)
	}
	if parsed.ResultCode != diam.Success {
		es := c.consumeControl(r, m)
		return append(es, c.discard(in, diam.ProtocolRejectedDWA, parsed.ResultCode)...)
	}
	if m.Header.CommandFlags&diam.ErrorFlag != 0 {
		return c.discard(in, diam.ProtocolInvalidDWA, 0)
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
	es := c.consumeControl(r, m)
	es = append(es, c.settle(r)...)
	if actions.Failback {
		es = append(es, c.notify(Notification{Kind: WatchdogNotice, Watchdog: next.State}))
	}
	return es
}

func (c *Core) consumeControl(r *control, m *diam.Message) []Effect {
	if r.answered {
		return nil
	}
	r.answered = true
	return []Effect{c.consumed(m)}
}

func (c *Core) consumed(m *diam.Message) Effect {
	e := c.effect(CompleteRequest)
	e.Notification.Message = metadata(m)
	return e
}
