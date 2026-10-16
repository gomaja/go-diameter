package sm

import (
	"math/rand"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/transport"
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

// clientConnectionDone preserves an outer wrapper's CloseNotify interception.
// Native byte streams report terminal reads before concurrent callbacks drain,
// without reading while a sequential callback or dispatch admission is blocked.
func clientConnectionDone(c diam.Conn) <-chan struct{} {
	for c != nil {
		if done, ok := transport.ReadDone(c); ok {
			return done
		}
		if n, ok := c.(diam.CloseNotifier); ok {
			return n.CloseNotify()
		}
		if n, ok := c.(interface{ Unwrap() diam.Conn }); ok {
			c = n.Unwrap()
		} else {
			return nil
		}
	}
	return nil
}
