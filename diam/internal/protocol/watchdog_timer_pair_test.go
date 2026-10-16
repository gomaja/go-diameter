package protocol

import (
	"testing"
	"time"
)

func TestWatchdogArmPreservesEffectsAndTokens(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, configured := range []time.Duration{0, 6 * time.Second} {
			for _, interval := range []time.Duration{-time.Second, 0, 9 * time.Second} {
				original := machine(t)
				original.cfg.WatchdogInterval = configured
				if active {
					original.arm(WatchdogTimer, epoch, time.Second)
				}
				candidate := *original
				effective := interval
				if effective <= 0 {
					effective = configured
				}
				want := original.stop(WatchdogTimer)
				want = append(want, original.arm(WatchdogTimer, epoch, effective)...)
				got := candidate.watchdogArm(epoch, interval)
				equal := (got == nil) == (want == nil) && len(got) == len(want)
				for i := 0; equal && i < len(got); i++ {
					a, b := got[i], want[i]
					equal = a.Kind == b.Kind && a.Connection == b.Connection && a.Timer == b.Timer && a.Token == b.Token && a.Deadline.Equal(b.Deadline)
				}
				if !equal || candidate.serial != original.serial || candidate.timers != original.timers {
					t.Fatalf("active=%t configured=%s interval=%s: effects=%+v want=%+v timers=%+v want=%+v serial=%d want=%d", active, configured, interval, got, want, candidate.timers, original.timers, candidate.serial, original.serial)
				}
			}
		}
	}
}

func TestWatchdogTimerReplacementAllocatesOneVector(t *testing.T) {
	c := machine(t)
	var effects []Effect
	allocations := testing.AllocsPerRun(100, func() { effects = c.watchdogArm(epoch, time.Second) })
	if len(effects) != 2 || effects[0].Kind != StopTimer || effects[1].Kind != ArmTimer {
		t.Fatalf("replacement effects=%+v", effects)
	}
	if allocations > 1 {
		t.Fatalf("watchdog timer replacement allocates %.0f vectors; want at most one", allocations)
	}
}
