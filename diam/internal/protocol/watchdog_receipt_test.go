package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

// Per-receipt state stays bounded while a selected watchdog writer has not
// reported its completion.
func TestWatchdogStalledReceiveStorageIsBounded(t *testing.T) {
	c := supervised(t, false)
	sent := grant(t, c, tick(t, c))
	for i := range 10000 {
		m := diam.NewRequest(999, 4, c.cfg.Dictionary).Answer(diam.Success)
		if i%2 == 0 {
			m = dwa(t, sent, diam.Success)
			m.Header.HopByHopID++
		}
		in := receive(m)
		in.Sequence, in.At = uint64(i+1), epoch.Add(7*time.Second+time.Duration(i)*time.Millisecond)
		c.Handle(in)
		if len(c.controls) != 1 || len(c.operations) != 1 || len(c.reservations) != 0 || c.deferredExpiry != nil {
			t.Fatal("stalled writer retained per-receipt protocol state")
		}
	}
	answer := receive(dwa(t, sent, diam.Success))
	answer.Sequence, answer.At = 10001, epoch.Add(18*time.Second)
	c.Handle(answer)
	deadline := c.Snapshot().Timer(WatchdogTimer).Deadline
	finished := complete(sent)
	finished.At = epoch.Add(20 * time.Second)
	c.Handle(finished)
	if c.Snapshot().Watchdog().Pending || len(c.Snapshot().Controls()) != 0 || len(c.operations) != 0 || deadline != answer.At.Add(6*time.Second) || c.Snapshot().Timer(WatchdogTimer).Deadline != deadline {
		t.Fatal("late writer completion lost early DWA credit or its receipt deadline")
	}
}

// The frontend draws jitter and supplies the interval on every transition.
// Activity, publication and a validated answer must each use their own draw.
func TestWatchdogRedrawsIntervalAtEachArm(t *testing.T) {
	c := supervised(t, false)
	activity := receive(diam.NewRequest(999, 4, c.cfg.Dictionary).Answer(diam.Success))
	activity.At, activity.Interval = epoch.Add(time.Second), 80*time.Second
	c.Handle(activity)
	if c.Snapshot().Timer(WatchdogTimer).Deadline != epoch.Add(81*time.Second) {
		t.Fatal("activity re-used an earlier interval")
	}
	sent := grant(t, c, tick(t, c))
	activity.At, activity.Interval = epoch.Add(82*time.Second), 90*time.Second
	c.Handle(activity)
	if c.Snapshot().Timer(WatchdogTimer).Deadline != epoch.Add(172*time.Second) {
		t.Fatal("prepublication activity lost its interval")
	}
	finished := complete(sent)
	finished.At, finished.Interval = epoch.Add(83*time.Second), 100*time.Second
	c.Handle(finished)
	if c.Snapshot().Timer(WatchdogTimer).Deadline != epoch.Add(183*time.Second) {
		t.Fatal("publication did not start the complete response window")
	}
	answer := receive(dwa(t, sent, diam.Success))
	answer.At, answer.Interval = epoch.Add(84*time.Second), 30*time.Second
	c.Handle(answer)
	if c.Snapshot().Timer(WatchdogTimer).Deadline != epoch.Add(114*time.Second) || c.Snapshot().Watchdog().Pending {
		t.Fatal("validated DWA did not use its independently drawn interval")
	}
}
