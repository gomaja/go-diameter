package watchdog

import "time"

// RFC 3539 §3.4.1 [1]: the minimum is applied to Twinit before jitter.
const (
	DefaultTw     = 30 * time.Second
	MinimumTw     = 6 * time.Second
	DefaultJitter = 2 * time.Second
)

// Tw implements RFC 3539 Appendix A SetWatchdog with uniform, inclusive
// nanosecond jitter. The caller supplies a seeded Int63n-compatible source.
// Configuration validation and test-only timing overrides belong to callers.
func Tw(twinit, jitter time.Duration, int63n func(int64) int64) time.Duration {
	if jitter == 0 {
		return twinit
	}
	return twinit - jitter + time.Duration(int63n(int64(2*jitter)+1))
}

// Window records an arm point and duration without scheduling a timer.
type Window struct {
	ArmedAt time.Time
	After   time.Duration
}

// Reset samples the injected clock and redraws the interval on every call
// (RFC 3539 §3.4.1 [1–2], Appendix A SetWatchdog). Callers own scheduling and
// arbitration between received activity and an expired window.
func Reset(now func() time.Time, next func() time.Duration) Window {
	return Window{ArmedAt: now(), After: next()}
}
