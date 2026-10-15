package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// sequenceModel is an independent, reduced RFC 6733 §§5.3–5.6/#108 oracle.
// It uses semantic events and its own state numbers, never Core guards or the
// watchdog transition implementation. Exact packet/error rows live in tables.
type sequenceModel struct {
	phase                                                                              int // 0 unadmitted, 1 outbound, 2 active, 3 draining, 4 dead, 5 retired
	initiator, started, candidate, callback, ready, frozen, localDPR, dprSent, cerSent bool
	handTimer, closeTimer                                                              bool
}

func (m *sequenceModel) step(action byte) {
	if m.phase >= 4 {
		return
	}
	switch action {
	case 0:
		if m.phase == 0 && !m.started {
			m.started = true
			m.handTimer = true
			if m.initiator {
				m.phase = 1
			}
		}
	case 1: // received valid CER
		switch m.phase {
		case 0:
			if m.initiator {
				m.end(4)
				break
			}
			if m.candidate {
				m.end(4)
			} else {
				m.candidate = true
			}
		case 1:
			m.end(4)
		}
	case 2:
		if m.phase == 0 && m.candidate {
			m.phase = 2
			m.candidate = false
			m.handTimer = false
		}
	case 3:
		if m.phase == 2 {
			m.callback = true
		} // CEA reply completed
	case 4:
		if m.phase == 2 && m.callback {
			m.ready = true
		}
	case 5: // application request
		if m.phase == 0 || m.phase == 1 {
			m.end(4)
		}
	case 6:
		if m.phase == 2 {
			m.phase = 3
			m.ready = false
			m.closeTimer = true
			m.localDPR = true
		}
	case 7:
		if m.phase == 3 {
			m.frozen = true
		}
	case 8:
		if m.phase == 1 {
			m.cerSent = true
		}
		if m.phase == 3 && m.frozen && m.localDPR {
			m.dprSent = true
		}
	case 9:
		if m.phase == 3 && m.dprSent {
			m.end(4)
		} else if m.phase == 0 || m.phase == 1 {
			m.end(4)
		}
	case 10:
		if m.handTimer || m.closeTimer {
			m.end(4)
		}
	case 11:
		m.end(5)
	case 12: // deliberately wrong connection: always ignored
	case 13:
		m.end(4)
	case 14: // received valid CEA
		if m.phase == 1 && m.cerSent {
			m.phase = 2
			m.callback = true
			m.handTimer = false
		} else if m.phase == 0 && !m.initiator {
			m.end(4)
		}
	case 15: // received DPR
		if m.phase == 0 || m.phase == 1 {
			m.end(4)
		} else if m.phase == 2 && m.ready {
			m.phase = 3
			m.ready = false
			m.closeTimer = true
		}
	case 16: // queue acceptance; queued responder CEA makes callback ready
	case 17: // write failure handled separately against a live send
	case 18: // uncorrelated DPA
		if m.phase == 0 || m.phase == 1 {
			m.end(4)
		}
	case 19: // stale candidate activation
	case 20:
		if m.phase == 0 && m.candidate {
			m.end(4)
		}
	case 21: // unsupported application handed back to core
	case 22: // owned application answer
		if m.phase == 0 || m.phase == 1 {
			m.end(4)
		}
	}
}
func (m *sequenceModel) end(phase int) {
	m.phase = phase
	m.candidate = false
	m.ready = false
	m.callback = false
	m.handTimer = false
	m.closeTimer = false
}
func modelPhase(p int) Phase { return [...]Phase{PreCER, WaitCEA, Open, Closing, Closed, Retired}[p] }

type sequenceRunner struct {
	c                           *Core
	candidate, admission, fence uint64
	reserve                     []Effect
	sends                       []Effect
	finished                    map[uint64]bool
	timers                      map[TimerKind]Effect
	leases                      map[uint32]Reservation
	pins                        map[uint64]int
	released                    map[uint64]bool
	completions                 map[NoticeKind]int
	cer, dpr                    Effect
}

func newRunner(c *Core) *sequenceRunner {
	return &sequenceRunner{c: c, finished: map[uint64]bool{}, timers: map[TimerKind]Effect{}, leases: map[uint32]Reservation{}, pins: map[uint64]int{}, released: map[uint64]bool{}, completions: map[NoticeKind]int{}}
}
func (r *sequenceRunner) lastSend() (Effect, bool) {
	for i := len(r.sends) - 1; i >= 0; i-- {
		if !r.finished[r.sends[i].Token] {
			return r.sends[i], true
		}
	}
	return Effect{}, false
}
func (r *sequenceRunner) observe(t testing.TB, in Input, es []Effect, wasTerminal bool) {
	t.Helper()
	if in.Kind == WriteResult {
		if in.Stage == WrittenStage || in.Err != nil {
			for _, send := range r.sends {
				if send.Token == in.Token && !r.finished[send.Token] {
					r.finished[send.Token] = true
					if send.Message.Header.CommandFlags&diam.RequestFlag != 0 {
						r.pins[r.leases[send.Message.Header.CommandCode].Token]--
					}
				}
			}
		}
	}
	for _, e := range es {
		if e.Connection != connection {
			t.Fatal("effect belongs to another generation")
		}
		if wasTerminal && e.Kind != ReleaseIDs {
			t.Fatalf("terminal core produced protocol effect %v", e.Kind)
		}
		switch e.Kind {
		case ValidatedCER:
			r.candidate = e.Token
		case Publish:
			r.admission = e.Token
		case FreezeAdmission:
			r.fence = e.Token
		case ReserveIDs:
			r.reserve = append(r.reserve, e)
		case ArmTimer:
			r.timers[e.Timer] = e
		case StopTimer:
			delete(r.timers, e.Timer)
		case Send:
			if e.Message == nil || e.Message.Header == nil {
				t.Fatal("nil send")
			}
			r.sends = append(r.sends, e)
			if e.Message.Header.CommandFlags&diam.RequestFlag != 0 {
				lease := r.leases[e.Message.Header.CommandCode]
				if r.released[lease.Token] {
					t.Fatal("request reused a released reservation")
				}
				r.pins[lease.Token]++
				if e.Message.Header.CommandCode == diam.CapabilitiesExchange {
					r.cer = e
				}
				if e.Message.Header.CommandCode == diam.DisconnectPeer {
					r.dpr = e
				}
			}
		case ReleaseIDs:
			token := e.Reservation.Token
			if r.pins[token] != 0 {
				t.Fatalf("reservation released with %d writer pins", r.pins[token])
			}
			if r.released[token] {
				t.Fatal("reservation released twice")
			}
			r.released[token] = true
		case Notify:
			n := e.Notification
			if (n.Kind == HandshakeNotice || n.Kind == DisconnectNotice) && n.Outcome != NotOpen && n.Outcome != AlreadyPending {
				r.completions[n.Kind]++
				if r.completions[n.Kind] > 1 {
					t.Fatal("control waiter completed twice")
				}
			}
		}
	}
}

func FuzzProtocolSequences(f *testing.F) {
	for _, seed := range [][]byte{{0, 0, 1, 2, 3, 4, 15, 7, 9}, {1, 0, 8, 14, 4, 6, 7, 8, 9}, {0, 1, 2, 11, 3, 4}, {1, 0, 11, 8}, {0, 1, 2, 16, 4, 6, 7, 8, 17}, {0, 0, 1, 2, 3, 4, 6, 7, 8, 9, 11}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 128 {
			data = data[:128]
		}
		cfg := configuration(t)
		cfg.Role = Responder
		if data[0]&1 != 0 {
			cfg.Role = Initiator
		}
		cfg.QueueWrites = data[0]&2 != 0
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		r := newRunner(c)
		model := sequenceModel{initiator: cfg.Role == Initiator}
		for index, b := range data[1:] {
			action := b % 23
			in := event(Start)
			in.At = epoch.Add(time.Duration(index) * time.Millisecond)
			switch action {
			case 0:
				in.Kind = Start
			case 1:
				in = receive(cer(t))
			case 2:
				in.Kind = Activate
				in.Token = r.candidate
			case 3:
				if send, ok := r.lastSend(); ok {
					in = complete(send)
				} else {
					in.Kind = WriteResult
				}
			case 4:
				in.Kind = ReleaseAdmission
				in.Token = r.admission
			case 5:
				in = receive(diam.NewRequest(999, 4, cfg.Dictionary))
			case 6:
				in.Kind = Disconnect
			case 7:
				in.Kind = Frozen
				in.Token = r.fence
			case 8:
				in.Kind = ReserveResult
				if len(r.reserve) > 0 {
					e := r.reserve[0]
					r.reserve = r.reserve[1:]
					in.Token = e.Token
					in.Reservation = Reservation{Token: 1000 + e.Token, Hop: uint32(e.Token), End: uint32(e.Token) + 100}
					r.leases[e.Command] = in.Reservation
				}
			case 9, 18:
				m := r.dpr.Message
				if m == nil {
					m = request(t, diam.DisconnectPeer)
				}
				answer, err := base.BuildDPA(m, remote(t).Local)
				if err != nil {
					t.Fatal(err)
				}
				in = receive(answer)
				if action == 18 {
					answer.Header.EndToEndID++
				}
			case 10:
				in.Kind = TimerExpired
				in.Timer = HandshakeTimer
				if model.phase == 3 {
					in.Timer = ClosingTimer
				}
				timer := r.timers[in.Timer]
				in.Token = timer.Token
				in.At = timer.Deadline
			case 11:
				in.Kind = Retire
			case 12:
				in = receive(cer(t))
				in.Connection.Generation++
			case 13:
				in.Kind = Abort
			case 14:
				m := r.cer.Message
				if m == nil {
					m = cer(t)
				}
				answer, err := base.BuildCEA(m, remote(t).Local, diam.Success)
				if err != nil {
					t.Fatal(err)
				}
				in = receive(answer)
			case 15:
				in = receive(request(t, diam.DisconnectPeer))
			case 16:
				in.Kind = WriteResult
				if send, ok := r.lastSend(); ok {
					in = complete(send)
					in.Stage = QueueStage
				}
			case 17:
				in.Kind = WriteResult
				if send, ok := r.lastSend(); ok {
					in = complete(send)
					in.Err = errors.New("synthetic write failure")
				}
			case 19:
				in.Kind = Activate
				in.Token = r.candidate + 999
			case 20:
				in.Kind = RejectCandidate
				in.Token = r.candidate
			case 21:
				in.Kind = Unhandled
				in.Message = diam.NewRequest(999, 4, cfg.Dictionary)
			case 22:
				in = receive(diam.NewMessage(999, 0, 4, 1, 2, cfg.Dictionary))
				in.Ownership = 99
			}
			before := c.Snapshot()
			wasTerminal := model.phase >= 4
			// Completions only matter when the runner still owns the operation.
			send, live := r.lastSend()
			switch action {
			case 3:
				if live && send.Message.Header.CommandCode == diam.CapabilitiesExchange && send.Message.Header.CommandFlags&diam.RequestFlag == 0 {
					model.step(action)
				}
			case 16:
				if cfg.QueueWrites && live && send.Message.Header.CommandCode == diam.CapabilitiesExchange && send.Message.Header.CommandFlags&diam.RequestFlag == 0 {
					model.step(3)
				}
			case 17:
				if live && !wasTerminal {
					model.end(4)
				}
			case 8:
				if in.Token != 0 {
					model.step(action)
				}
			default:
				model.step(action)
			}
			es := c.Handle(in)
			if action == 12 && (!reflectSnapshot(before, c.Snapshot()) || len(es) != 0) {
				t.Fatal("stale generation affected core")
			}
			r.observe(t, in, es, wasTerminal)
			if got := c.Snapshot().Phase(); got != modelPhase(model.phase) {
				t.Fatalf("sequence=%v index=%d action=%d phase=%v model=%d effects=%v", data, index, action, got, model.phase, kinds(es))
			}
			if c.Snapshot().Ready() != model.ready {
				t.Fatalf("sequence=%v index=%d admission=%v model=%v", data, index, c.Snapshot().Ready(), model.ready)
			}
			for _, e := range es {
				allowed := model.phase == 2 && model.ready || model.phase == 3 && in.Ownership != 0
				if e.Kind == Admit && !allowed {
					t.Fatal("application admitted outside Open/drain ownership")
				}
				if e.Kind == Send && e.Message.Header.CommandFlags&diam.RequestFlag != 0 && model.phase == 3 && (!model.frozen || e.Message.Header.CommandCode != diam.DisconnectPeer) {
					t.Fatal("request published outside Closing fence")
				}
			}
		}
	})
}
func reflectSnapshot(a, b Snapshot) bool {
	return a.Phase() == b.Phase() && a.Candidate() == b.Candidate() && a.Admission() == b.Admission() && a.Ready() == b.Ready() && a.Watchdog() == b.Watchdog()
}
