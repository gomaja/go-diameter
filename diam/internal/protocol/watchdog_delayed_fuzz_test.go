package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

// RFC 3539 §3.4.1/Appendix A; #108/#125: allocation, queue admission,
// publication, answers and writer disposal are separately scheduled events.
// This oracle uses its own protocol states and lease ledger, never Machine.Step.
type delayedProbe struct {
	logical, pin, queued, answered bool
	id                             uint64
	send                           Effect
}

type delayedWatchdog struct {
	watchdogOracle
	tentative *watchdogOracle
	alloc     bool
	current   *delayedProbe
	leases    map[uint64]*delayedProbe
	deadline  time.Time
}

func (o *delayedWatchdog) selectProbe() {
	next := o.watchdogOracle
	next.pending, next.outstanding = true, true
	o.tentative, o.alloc = &next, true
	o.deadline = time.Time{}
}

func (o *delayedWatchdog) expiry(at time.Time) {
	if o.status >= 3 || o.deadline.IsZero() {
		return
	}
	if o.tentative != nil {
		o.deadline = at.Add(6 * time.Second)
		return
	}
	// Appendix A closes SUSPECT on expiry even if the unpublished writer
	// was subsequently cancelled and therefore no longer owns Pending.
	if o.status == 1 {
		o.end(3)
		return
	}
	if !o.pending {
		o.selectProbe()
		return
	}
	if o.status == 2 && o.answers < 0 {
		o.end(3)
		return
	}
	if o.status == 0 {
		o.status = 1
	} else {
		o.answers = -1
	}
	o.deadline = at.Add(6 * time.Second)
}

func (o *delayedWatchdog) end(status int) {
	if o.status >= 3 && (o.status != 5 || status == 5) {
		return
	}
	o.status, o.pending = status, false
	o.tentative, o.deadline = nil, time.Time{}
	for _, p := range o.leases {
		p.logical = false
	}
}

func (o *delayedWatchdog) publication(p *delayedProbe, at time.Time) {
	if o.status < 3 && p.logical && o.tentative != nil {
		o.watchdogOracle = *o.tentative
		o.tentative = nil
		o.deadline = at.Add(6 * time.Second)
	}
}

func FuzzWatchdogDelayedCompletions(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0, 1, 10, 4},         // selected DWR loses the gate after Closing
		{0, 0, 1, 5, 0, 1, 4, 3}, // early answer, new probe, old skipped writer
		{2, 0, 1, 2, 5, 0, 1, 3, 4},
		{1, 8, 0, 1, 5, 0, 1, 2, 3, 12},
		{0, 0, 8, 0, 1, 8, 0, 4, 0, 1, 3}, // allocation/write held over activity/expiry
		{3, 1, 2, 7, 8, 0, 3, 0, 9, 5, 12},
		{0, 0, 11, 1, 13, 12}, {0, 0, 14},
	} {
		f.Add(seed)
	}
	// Real executor failures are distinct from SkippedStage: even an answered
	// probe or Closing connection must fail, while retirement remains latched.
	for _, mode := range []byte{0, 1, 2, 3} {
		for _, failure := range []byte{17, 18, 19, 20, 21, 22} {
			for _, interleave := range [][]byte{
				nil, {8}, {9}, {5}, {7}, {10}, {12}, {8, 5},
				{2}, {2, 8}, {2, 9}, {2, 5}, {2, 7}, {2, 10}, {2, 12},
				{5, 0, 1}, {5, 0, 1, 10}, {5, 0, 1, 12},
			} {
				seed := append([]byte{mode, 0, 1}, interleave...)
				f.Add(append(seed, failure))
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 97 {
			data = data[:97]
		}
		c := machine(t, func(cfg *Config) {
			cfg.Watchdog, cfg.WatchdogInterval = true, 6*time.Second
			cfg.Recovery, cfg.QueueWrites = data[0]&1 != 0, data[0]&2 != 0
		})
		// Finish only the capability exchange synchronously. Every subsequent
		// watchdog allocation and writer remains pending until a fuzz action.
		sent := find(t, accept(t, c), Send)
		ready := find(t, c.Handle(complete(sent)), HandshakeReady)
		release := event(ReleaseAdmission)
		release.Token = ready.Token
		o := delayedWatchdog{leases: make(map[uint64]*delayedProbe), deadline: epoch.Add(6 * time.Second)}
		if c.cfg.Recovery {
			o.status = 2
			o.selectProbe()
		}
		var allocation Effect
		var writes []*delayedProbe
		serial := uint64(1000)
		handshakeCompletions := 1
		var completion *delayedProbe
		var disconnectCompletion *Effect
		var disconnectToken uint64
		disconnectWaiting := false
		expectTermination := func() {
			if disconnectWaiting {
				disconnectCompletion = &Effect{Token: disconnectToken, Notification: Notification{Outcome: ConnectionClosed}}
				disconnectWaiting = false
			}
		}
		// Effects supply execution tokens, not the expected protocol state.
		collect := func(es []Effect, granted *delayedProbe) {
			for _, e := range es {
				switch e.Kind {
				case CompleteRequest:
					m := e.Notification.Message
					if completion == nil || !m.HasHeader || m.Header.CommandCode != diam.DeviceWatchdog || m.Header.HopByHopID != uint32(completion.id) || m.Header.EndToEndID != uint32(completion.id+1000) {
						t.Fatal("duplicate, unsolicited or uncorrelated native completion")
					}
					completion = nil
				case Notify:
					if e.Notification.Kind == HandshakeNotice {
						handshakeCompletions--
						if handshakeCompletions < 0 || e.Notification.Outcome != Completed {
							t.Fatal("duplicate or failed handshake completion")
						}
					}
					if e.Notification.Kind == DisconnectNotice {
						if disconnectCompletion == nil || e.Token != disconnectCompletion.Token || e.Notification.Outcome != disconnectCompletion.Notification.Outcome {
							t.Fatalf("unexpected disconnect completion: %+v", e)
						}
						disconnectCompletion = nil
					}
				case ReserveIDs:
					if !o.alloc || allocation.Token != 0 || e.Command != diam.DeviceWatchdog {
						t.Fatal("overlapping or unsolicited allocation")
					}
					allocation = e
				case Send:
					if granted == nil || !granted.logical || granted.send.Token != 0 {
						t.Fatal("unexpected control publication")
					}
					granted.send = e
					writes = append(writes, granted)
				case ReleaseIDs:
					p := o.leases[e.Reservation.Token]
					if p == nil || p.logical || p.pin || e.Reservation.Hop != uint32(p.id) || e.Reservation.End != uint32(p.id+1000) {
						t.Fatalf("premature or duplicate lease release: %+v", p)
					}
					delete(o.leases, p.id)
				}
			}
		}
		collect(c.Handle(release), nil)
		at := epoch
		step := func(action byte) {
			at = at.Add(time.Second)
			in := event(Receive)
			in.At = at
			var granted *delayedProbe
			switch action {
			case 0:
				in.Kind, in.Timer = TimerExpired, WatchdogTimer
				in.Token = c.Snapshot().Timer(WatchdogTimer).Token
				if o.deadline.After(at) {
					at, in.At = o.deadline, o.deadline
				}
				o.expiry(at)
			case 1, 14:
				if allocation.Token == 0 {
					return
				}
				in.Kind, in.Token = ReserveResult, allocation.Token
				allocation = Effect{}
				o.alloc = false
				if action == 14 {
					in.Err = diam.ErrConnectionClosing
					if o.status < 3 || o.status == 5 {
						o.end(3)
					}
				} else {
					serial++
					in.Reservation = Reservation{Token: serial, Hop: uint32(serial), End: uint32(serial + 1000)}
					granted = &delayedProbe{id: serial, logical: o.status < 3, pin: o.status < 3}
					o.leases[serial] = granted
					if granted.logical {
						o.current = granted
					}
				}
			case 2, 3, 4, 15, 16, 17, 18, 19, 20, 21, 22:
				if len(writes) == 0 {
					return
				}
				index := 0
				if action == 15 || action == 16 || action >= 20 {
					index = len(writes) - 1
				}
				p := writes[index]
				// Queue admission has only one result and exists only for the
				// queued frontend. A rejection is terminal, never a skip.
				if (action == 17 || action == 20) && (!c.cfg.QueueWrites || p.queued) {
					return
				}
				in = complete(p.send)
				in.At = at
				if action == 2 {
					in.Stage = QueueStage
					if !p.queued && c.cfg.QueueWrites {
						o.publication(p, at)
					}
					p.queued = true
				} else {
					p.pin = false
					writes = append(writes[:index], writes[index+1:]...)
					if action >= 17 {
						switch action {
						case 17, 20:
							in.Stage, in.Bytes, in.Err = QueueStage, 0, errors.New("queue rejected")
						case 18, 21:
							in.Bytes-- // no error: the core must detect a short write
						case 19, 22:
							in.Err = errors.New("transport write failed")
							if action == 19 {
								in.Bytes = 0
							}
							// Action 22 reports a full byte count with an error:
							// error handling must not rely on short-write detection.
						}
						o.end(3)
					} else if action == 4 || action == 16 {
						in.Stage, in.Bytes, in.Err = SkippedStage, 0, diam.ErrRequestCompleted
						if p.logical {
							p.logical = false
							o.tentative, o.pending = nil, false
							if o.status < 3 && o.deadline.IsZero() {
								o.deadline = at.Add(6 * time.Second)
							}
						}
					} else if !p.queued || !c.cfg.QueueWrites {
						o.publication(p, at)
					}
				}
			case 5, 6, 7:
				if o.current == nil {
					in.Message = diam.NewMessage(diam.DeviceWatchdog, 0, 0, 99, 100, c.cfg.Dictionary)
				} else {
					in.Message = dwa(t, o.current.send, diam.Success)
				}
				if action == 6 {
					in.Message.Header.HopByHopID++
				} else if o.current != nil && action == 7 {
					in.Message = dwa(t, o.current.send, diam.UnableToComply)
				}
				if o.status < 3 {
					o.deadline = at.Add(6 * time.Second)
					if o.current != nil && o.current.logical && action != 6 {
						if !o.current.answered {
							completion = o.current
						}
						o.current.answered = true
						if action == 5 {
							if o.tentative != nil {
								o.watchdogOracle, o.tentative = *o.tentative, nil
							}
							o.apply(1)
							o.current.logical = false
						}
					}
				}
			case 8, 9:
				in.Message = cer(t)
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
				if action == 9 {
					in.Message, in.Error = diam.NewRequest(999, 4, c.cfg.Dictionary), nil
				}
				if o.status < 3 {
					o.deadline = at.Add(6 * time.Second)
					if action == 9 {
						o.apply(5)
					}
				}
			case 10:
				in.Kind, in.Token = Disconnect, uint64(at.UnixNano())
				if disconnectWaiting {
					disconnectCompletion = &Effect{Notification: Notification{Outcome: AlreadyPending}}
				}
				if o.status < 3 {
					disconnectWaiting, disconnectToken = true, in.Token
					// Closing stops Tw but preserves protocol Pending until a
					// skipped writer or connection termination disposes it.
					o.status, o.deadline = 5, time.Time{}
				}
			case 11:
				in.Kind = TransportLost
				o.end(3)
			case 12:
				in.Kind = Retire
				o.end(4)
			case 13:
				in.Connection.Generation++
				in.Message = cer(t)
			}
			if o.status == 3 || o.status == 4 {
				expectTermination()
			}
			es := c.Handle(in)
			if action == 13 && len(es) != 0 {
				t.Fatal("stale generation produced effects")
			}
			collect(es, granted)
			if o.alloc != (allocation.Token != 0) {
				t.Fatal("missing allocation obligation")
			}
			if handshakeCompletions != 0 {
				t.Fatal("missing handshake waiter completion")
			}
			if completion != nil {
				t.Fatal("missing native completion")
			}
			if disconnectCompletion != nil {
				t.Fatal("missing disconnect waiter completion")
			}
			s := c.Snapshot()
			if o.status < 3 {
				want := [...]string{"OKAY", "SUSPECT", "REOPEN"}[o.status]
				if s.Phase() != Open || string(s.Watchdog().State) != want || s.Watchdog().Pending != o.pending || s.Watchdog().NumDWA != o.answers || s.Timer(WatchdogTimer).Deadline != o.deadline {
					t.Fatalf("sequence=%v action=%d got=%+v timer=%+v oracle=%+v", data, action, s.Watchdog(), s.Timer(WatchdogTimer), o)
				}
			} else if s.Phase() != [...]Phase{Closed, Retired, Closing}[o.status-3] {
				t.Fatalf("sequence=%v action=%d phase=%v oracle=%+v", data, action, s.Phase(), o)
			}
			if o.status == 3 || o.status == 4 {
				if s.Ready() || s.Watchdog().Pending || s.Timer(WatchdogTimer) != (TimerSnapshot{}) || s.Timer(ClosingTimer) != (TimerSnapshot{}) {
					t.Fatal("terminal generation retained readiness, Pending or a timer")
				}
			}
			for _, control := range s.Controls() {
				p := o.leases[control.Reservation.Token]
				if p == nil || control.Command != diam.DeviceWatchdog || control.Logical != p.logical || control.Answered != p.answered || (control.Writers == 1) != p.pin || control.Writers < 0 || control.Writers > 1 {
					t.Fatalf("control ownership differs from lease ledger: control=%+v lease=%+v", control, p)
				}
			}
			for _, p := range o.leases {
				if !p.logical && !p.pin {
					t.Fatal("eligible lease was not released")
				}
			}
		}
		for _, raw := range data[1:] {
			step(raw % 23)
		}
		// Complete every delayed executor obligation, even after retirement.
		step(12)
		step(1)
		for len(writes) > 0 {
			step(4)
		}
		if len(o.leases) != 0 || len(c.Snapshot().Controls()) != 0 || len(c.reservations) != 0 || len(c.operations) != 0 || disconnectWaiting {
			t.Fatal("executor leaked reservations, writers or a disconnect waiter")
		}
	})
}
