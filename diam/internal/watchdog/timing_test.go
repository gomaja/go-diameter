package watchdog

import (
	"testing"
	"time"
)

// RFC 3539 §3.4.1 [1], Appendix A SetWatchdog: the 6s floor applies
// before jitter, and a fresh uniform draw covers both endpoints on each reset.
func TestRFC3539Tw(t *testing.T) {
	if DefaultTw != 30*time.Second || MinimumTw != 6*time.Second || DefaultJitter != 2*time.Second {
		t.Fatalf("defaults: %s %s %s", DefaultTw, MinimumTw, DefaultJitter)
	}
	for _, row := range []struct {
		name         string
		init, jitter time.Duration
		draw         int64
		want         time.Duration
	}{
		{"default_lower", DefaultTw, DefaultJitter, 0, 28 * time.Second},
		{"default_middle", DefaultTw, DefaultJitter, int64(DefaultJitter), 30 * time.Second},
		{"default_upper", DefaultTw, DefaultJitter, int64(2 * DefaultJitter), 32 * time.Second},
		{"minimum_lower", MinimumTw, DefaultJitter, 0, 4 * time.Second},
		{"minimum_upper", MinimumTw, DefaultJitter, int64(2 * DefaultJitter), 8 * time.Second},
		{"no_jitter", time.Millisecond, 0, 0, time.Millisecond},
	} {
		t.Run(row.name, func(t *testing.T) {
			calls := 0
			got := Tw(row.init, row.jitter, func(n int64) int64 {
				calls++
				if n != int64(2*row.jitter)+1 {
					t.Fatalf("draw range = %d", n)
				}
				return row.draw
			})
			if got != row.want {
				t.Fatalf("Tw = %s, want %s", got, row.want)
			}
			wantCalls := 1
			if row.jitter == 0 {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("draws = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestResetUsesInjectedClockAndRedraws(t *testing.T) {
	now := time.Unix(1234, 0)
	draws := []int64{0, int64(DefaultJitter), int64(2 * DefaultJitter)}
	index := 0
	next := func() time.Duration {
		return Tw(DefaultTw, DefaultJitter, func(int64) int64 { draw := draws[index]; index++; return draw })
	}
	for _, want := range []time.Duration{28 * time.Second, 30 * time.Second, 32 * time.Second} {
		clockCalls := 0
		window := Reset(func() time.Time { clockCalls++; return now }, next)
		if window.ArmedAt != now || window.After != want || clockCalls != 1 {
			t.Fatalf("Reset = %+v, clock calls %d; want %s / %s", window, clockCalls, now, want)
		}
		now = now.Add(time.Second)
	}
	if index != 3 {
		t.Fatalf("draws = %d, want 3", index)
	}
}
