package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

// watchdogOracle independently encodes RFC 3539 §3.4.1/Appendix A and #108's
// validation policy. It deliberately does not call watchdog.Machine.Step.
type watchdogOracle struct {
	status               int // 0 healthy, 1 suspect, 2 recovering, 3 closed, 4 retired, 5 closing
	pending, outstanding bool
	answers              int
}

func (o *watchdogOracle) apply(action byte) {
	if o.status == 5 && action == 6 {
		o.status, o.pending = 4, false
	}
	if o.status >= 3 {
		return
	}
	switch action {
	case 0: // timer expiry, allocation and publication succeed
		switch o.status {
		case 0:
			if o.pending {
				o.status = 1
			} else {
				o.pending, o.outstanding = true, true
			}
		case 1:
			o.status, o.pending = 3, false
		case 2:
			if !o.pending {
				o.pending, o.outstanding = true, true
			} else if o.answers < 0 {
				o.status, o.pending = 3, false
			} else {
				o.answers = -1
			}
		}
	case 1: // valid successful correlated DWA
		if o.outstanding {
			o.pending, o.outstanding = false, false
			if o.status == 1 {
				o.status = 0
			}
			if o.status == 2 {
				o.answers++
				if o.answers == 3 {
					o.status = 0
				}
			}
		}
	case 2, 3, 4: // mismatched DWA, rejected DWA, malformed repeated CER: activity only
	case 5: // valid non-DWA recovers without clearing Pending
		if o.status == 1 {
			o.status = 0
		}
	case 6:
		o.status, o.pending = 4, false
	case 7:
		o.status = 5
	case 8: // stale generation
	}
}

func FuzzWatchdogSequences(f *testing.F) {
	for _, seed := range [][]byte{{0, 0, 0, 2, 4, 5, 1, 0, 0, 0}, {1, 1, 0, 1, 0, 1}, {1, 0, 1, 0, 0, 0}, {2, 0, 3, 2, 1, 0, 7, 0}, {0, 0, 6, 1, 5, 0, 8}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 65 {
			data = data[:65]
		}
		c := machine(t, func(cfg *Config) {
			cfg.Watchdog = true
			cfg.WatchdogInterval = 6 * time.Second
			cfg.Recovery = data[0]&1 != 0
			cfg.QueueWrites = data[0]&2 != 0
		})
		oracle := watchdogOracle{}
		var selected Effect
		serial := uint64(1000)
		at := epoch
		// Effect executor supplies deterministic IDs and completes selected sends.
		var execute func([]Effect)
		execute = func(es []Effect) {
			for _, e := range es {
				switch e.Kind {
				case ReserveIDs:
					serial++
					in := event(ReserveResult)
					in.At = at
					in.Token = e.Token
					in.Reservation = Reservation{Token: serial, Hop: uint32(serial), End: uint32(serial + 1000)}
					execute(c.Handle(in))
				case Send:
					if e.Message.Header.CommandCode == diam.DeviceWatchdog && e.Message.Header.CommandFlags&diam.RequestFlag != 0 {
						selected = e
					}
					done := complete(e)
					done.At = at
					if c.cfg.QueueWrites {
						queued := done
						queued.Stage = QueueStage
						execute(c.Handle(queued))
					}
					execute(c.Handle(done))
				}
			}
		}
		execute(accept(t, c))
		release := event(ReleaseAdmission)
		release.Token = c.Snapshot().Admission()
		execute(c.Handle(release))
		if c.cfg.Recovery {
			oracle.status, oracle.pending, oracle.outstanding = 2, true, true
		}
		for index, raw := range data[1:] {
			action := raw % 9
			at = at.Add(time.Second)
			in := event(Receive)
			in.At = at
			switch action {
			case 0:
				timer := c.Snapshot().Timer(WatchdogTimer)
				in.Kind = TimerExpired
				in.Timer = WatchdogTimer
				in.Token = timer.Token
				if timer.Deadline.After(at) {
					at = timer.Deadline
					in.At = at
				}
			case 1, 2, 3:
				if selected.Message == nil {
					in.Message = diam.NewMessage(diam.DeviceWatchdog, 0, 0, 99, 100, c.cfg.Dictionary)
				} else {
					in.Message = dwa(t, selected, diam.Success)
				}
				if action == 2 {
					in.Message.Header.HopByHopID++
				}
				if action == 3 && selected.Message != nil {
					in.Message = dwa(t, selected, diam.UnableToComply)
				}
			case 4:
				in.Message = cer(t)
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
			case 5:
				in.Message = diam.NewRequest(999, 4, c.cfg.Dictionary)
			case 6:
				in.Kind = Retire
			case 7:
				in.Kind = Disconnect
			case 8:
				in.Connection.Generation++
				in.Message = cer(t)
			}
			before := c.Snapshot()
			oracle.apply(action)
			es := c.Handle(in)
			for _, e := range es {
				if (action == 1 || action == 2 || action == 3) && e.Kind == Send {
					t.Fatal("answered an answer")
				}
				if action == 8 {
					t.Fatal("stale generation produced effect")
				}
			}
			execute(es)
			s := c.Snapshot()
			wd := s.Watchdog()
			if oracle.status < 3 {
				want := [...]string{"OKAY", "SUSPECT", "REOPEN"}[oracle.status]
				if s.Phase() != Open || string(wd.State) != want || wd.Pending != oracle.pending || wd.NumDWA != oracle.answers {
					t.Fatalf("sequence=%v index=%d action=%d got=%+v phase=%v oracle=%+v", data, index, action, wd, s.Phase(), oracle)
				}
				if action >= 1 && action <= 5 && s.Timer(WatchdogTimer).Deadline != at.Add(6*time.Second) {
					t.Fatal("activity used processing time")
				}
			} else {
				want := [...]Phase{Closed, Retired, Closing}[oracle.status-3]
				if s.Phase() != want {
					t.Fatalf("terminal phase=%v want=%v sequence=%v", s.Phase(), want, data)
				}
			}
			if action == 8 && !reflectSnapshot(before, s) {
				t.Fatal("stale input mutated state")
			}
		}
	})
}
