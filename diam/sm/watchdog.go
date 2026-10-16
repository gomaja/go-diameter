package sm

import (
	"math/rand"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

type watchdogTiming struct {
	floor  time.Duration
	jitter time.Duration
}

func (t *watchdogTiming) parameters() (floor, jitter time.Duration) {
	if t != nil {
		return t.floor, t.jitter
	}
	return watchdog.MinimumTw, watchdog.DefaultJitter
}

func jitteredTw(twinit, jitter time.Duration) time.Duration {
	return watchdog.Tw(twinit, jitter, rand.Int63n)
}

// connectionDone honors the first wrapper exposing either lifecycle interface.
// At the same layer DispatchDone takes precedence and avoids CloseNotify's TCP
// read pump. An outer CloseNotifier still intercepts closure.
func connectionDone(c diam.Conn) <-chan struct{} {
	for c != nil {
		switch n := c.(type) {
		case interface{ DispatchDone() <-chan struct{} }:
			return n.DispatchDone()
		case diam.CloseNotifier:
			return n.CloseNotify()
		case interface{ Unwrap() diam.Conn }:
			c = n.Unwrap()
		default:
			return nil
		}
	}
	return nil
}
