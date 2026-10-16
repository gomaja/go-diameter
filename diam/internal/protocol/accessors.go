package protocol

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// Phase returns the current phase within the caller's serialization domain.
func (c *Core) Phase() Phase { return c.phase }

// Ready reports whether admission callbacks have completed within the caller's
// serialization domain.
func (c *Core) Ready() bool { return c.ready }

// Progress carries scalar protocol state for executors that publish peer
// eligibility. Capability/error evidence is copied only by Snapshot.
type Progress struct {
	Phase    Phase
	Ready    bool
	Watchdog watchdog.Machine
	Timers   [timerCount]TimerSnapshot
	Controls [3]ControlSnapshot
}

func (c *Core) Progress() Progress {
	p := Progress{Phase: c.phase, Ready: c.ready, Watchdog: c.wd, Timers: c.timers}
	for i, command := range [...]uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		if r := c.controls[command]; r != nil {
			p.Controls[i] = ControlSnapshot{Command: r.command, Reservation: r.reservation, Logical: r.logical, Answered: r.answered, Writers: r.writers}
		}
	}
	return p
}
