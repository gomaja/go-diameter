package protocol

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type stateShape struct {
	phase                                                      Phase
	candidate, admission, ready, frozen, handTimer, closeTimer bool
	controls                                                   int
}

func shape(c *Core) stateShape {
	s := c.Snapshot()
	return stateShape{s.Phase(), s.Candidate() != 0, s.Admission() != 0, s.Ready(), s.Frozen(), s.Timer(HandshakeTimer).Token != 0, s.Timer(ClosingTimer).Token != 0, len(s.Controls())}
}

var shapes = map[string]stateShape{
	"pre":           {phase: PreCER},
	"candidate":     {phase: PreCER, candidate: true, handTimer: true},
	"hook":          {phase: PreCER, handTimer: true},
	"allocating":    {phase: WaitCEA, handTimer: true},
	"waiting":       {phase: WaitCEA, handTimer: true, controls: 1},
	"cea-write":     {phase: Open, admission: true},
	"admission":     {phase: Open, admission: true},
	"open":          {phase: Open, admission: true, ready: true},
	"closing-fence": {phase: Closing, admission: true, closeTimer: true},
	"closing":       {phase: Closing, admission: true, closeTimer: true, frozen: true, controls: 1},
	"closed":        {phase: Closed},
	"retired":       {phase: Retired},
}

type matrixFixture struct {
	core                               *Core
	candidate, hook, allocation, fence uint64
	send                               Effect
}

func matrixSetup(t testing.TB, name string) matrixFixture {
	t.Helper()
	f := matrixFixture{core: machine(t)}
	switch name {
	case "pre":
		return f
	case "candidate", "hook":
		f.core.cfg.Hooks = name == "hook"
		f.core.Handle(event(Start))
		es := f.core.Handle(receive(cer(t)))
		if name == "hook" {
			f.hook = find(t, es, RunHook).Token
		} else {
			f.candidate = find(t, es, ValidatedCER).Token
		}
	case "allocating", "waiting":
		f.core = machine(t, func(cfg *Config) { cfg.Role = Initiator })
		es := f.core.Handle(event(Start))
		f.allocation = find(t, es, ReserveIDs).Token
		if name == "waiting" {
			f.send = grant(t, f.core, es)
			f.core.Handle(complete(f.send))
			f.allocation = 0
		}
	case "cea-write", "admission":
		f.send = find(t, accept(t, f.core), Send)
		if name == "admission" {
			f.core.Handle(complete(f.send))
		}
	case "open":
		f.core = opened(t)
	case "closing-fence", "closing":
		f.core = opened(t)
		es := f.core.Handle(event(Disconnect))
		f.fence = find(t, es, FreezeAdmission).Token
		if name == "closing" {
			in := event(Frozen)
			in.Token = f.fence
			f.send = grant(t, f.core, f.core.Handle(in))
			f.core.Handle(complete(f.send))
			f.fence = 0
		}
	case "closed":
		f.core.Handle(event(Abort))
	case "retired":
		f.core.Handle(event(Retire))
	}
	if got := shape(f.core); got != shapes[name] {
		t.Fatalf("fixture %s=%+v want=%+v", name, got, shapes[name])
	}
	return f
}
func matrixInput(t testing.TB, name string, k InputKind, f matrixFixture) Input {
	t.Helper()
	in := event(k)
	switch k {
	case Receive:
		switch name {
		case "pre", "candidate":
			in.Message = cer(t)
		case "allocating":
			m, _ := base.BuildCEA(cer(t), remote(t).Local, diam.Success)
			in.Message = m
		case "waiting":
			m, _ := base.BuildCEA(f.send.Message, remote(t).Local, diam.Success)
			in.Message = m
		case "open":
			in.Message = request(t, diam.DeviceWatchdog)
		case "closing":
			m, _ := base.BuildDPA(f.send.Message, remote(t).Local)
			in.Message = m
		default:
			in.Message = diam.NewRequest(999, 4, f.core.cfg.Dictionary)
		}
	case Continue:
		in.Token = f.hook
	case Activate, RejectCandidate:
		in.Token = f.candidate
	case ReleaseAdmission:
		in.Token = f.core.Snapshot().Admission()
	case ReserveResult:
		in.Token = f.allocation
		in.Reservation = Reservation{Token: 123, Hop: 30, End: 40}
	case WriteResult:
		if f.send.Message != nil {
			in = complete(f.send)
		}
	case Frozen:
		in.Token = f.fence
	case TimerExpired:
		in.Timer = HandshakeTimer
		if name == "closing" || name == "closing-fence" {
			in.Timer = ClosingTimer
		}
		timer := f.core.Snapshot().Timer(in.Timer)
		in.Token = timer.Token
		in.At = timer.Deadline
	case Unhandled:
		in.Message = diam.NewRequest(999, 4, f.core.cfg.Dictionary)
	}
	return in
}

type matrixExpectation struct {
	effects []EffectKind
	next    string
	state   *stateShape
}

func expected(es ...EffectKind) matrixExpectation { return matrixExpectation{effects: es} }
func next(name string, es ...EffectKind) matrixExpectation {
	return matrixExpectation{effects: es, next: name}
}

// RFC 6733 §§5.3–5.6 and #108: all 16 input kinds in every phase, plus
// validated candidate, hook, CEA-write and handshake-callback substates. The
// literal effect rows are an external contract, not calls to production guards.
func TestEveryPhaseInputPair(t *testing.T) {
	rows := map[string]map[InputKind]matrixExpectation{
		"pre": {
			Start:      {effects: []EffectKind{ArmTimer}, state: &stateShape{phase: PreCER, handTimer: true}},
			Receive:    {effects: []EffectKind{ValidatedCER}, state: &stateShape{phase: PreCER, candidate: true}},
			Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", Close), TransportLost: next("closed", Close), Retire: next("retired"),
		},
		"candidate": {
			Receive: next("closed", StopTimer, Close, Notify), Activate: next("cea-write", StopTimer, Publish, Send), RejectCandidate: next("closed", StopTimer, Close),
			TimerExpired: next("closed", StopTimer, Close, Notify), Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, Close), TransportLost: next("closed", StopTimer, Close), Retire: next("retired", StopTimer),
		},
		"hook": {
			Receive: expected(Hold), Continue: next("candidate", ValidatedCER), TimerExpired: next("closed", StopTimer, Close, Notify), Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, Close), TransportLost: next("closed", StopTimer, Close), Retire: next("retired", StopTimer),
		},
		"allocating": {
			Receive: expected(Discard, Notify), ReserveResult: {effects: []EffectKind{Send}, state: &stateShape{phase: WaitCEA, handTimer: true, controls: 1}},
			TimerExpired: next("closed", StopTimer, Close, Notify, Notify), Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, Close, Notify), TransportLost: next("closed", StopTimer, Close, Notify), Retire: next("retired", StopTimer, Notify),
		},
		"waiting": {
			Receive: next("admission", CompleteRequest, ReleaseIDs, StopTimer, Publish, HandshakeReady), TimerExpired: next("closed", StopTimer, ReleaseIDs, Close, Notify, Notify), Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, ReleaseIDs, Close, Notify), TransportLost: next("closed", StopTimer, ReleaseIDs, Close, Notify), Retire: next("retired", StopTimer, ReleaseIDs, Notify),
		},
		"cea-write": {
			Receive: expected(Hold), WriteResult: next("admission", HandshakeReady), Disconnect: next("closing-fence", ArmTimer, FreezeAdmission), Unhandled: expected(Discard), Abort: next("closed", CancelSend, Close, Notify), TransportLost: next("closed", CancelSend, Close, Notify), Retire: next("retired", CancelSend, Notify),
		},
		"admission": {
			Receive: expected(Hold), ReleaseAdmission: next("open", Notify), Disconnect: next("closing-fence", ArmTimer, FreezeAdmission), Unhandled: expected(Discard), Abort: next("closed", Close, Notify), TransportLost: next("closed", Close, Notify), Retire: next("retired", Notify),
		},
		"open": {
			Receive: expected(Send), Disconnect: next("closing-fence", ArmTimer, FreezeAdmission), Unhandled: expected(Send), Abort: next("closed", Close), TransportLost: next("closed", Close), Retire: next("retired"),
		},
		"closing-fence": {
			Receive: expected(Discard), Frozen: {effects: []EffectKind{ReserveIDs}, state: &stateShape{phase: Closing, admission: true, closeTimer: true, frozen: true}}, TimerExpired: {effects: []EffectKind{StopTimer, Close, Notify, Notify}, state: &stateShape{phase: Closed}}, Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, Close, Notify), TransportLost: next("closed", StopTimer, Close, Notify), Retire: next("retired", StopTimer, Notify),
		},
		"closing": {
			Receive: next("closed", ReleaseIDs, StopTimer, Close, Notify), TimerExpired: next("closed", StopTimer, ReleaseIDs, Close, Notify, Notify), Disconnect: expected(Notify), Unhandled: expected(Discard), Abort: next("closed", StopTimer, ReleaseIDs, Close, Notify), TransportLost: next("closed", StopTimer, ReleaseIDs, Close, Notify), Retire: next("retired", StopTimer, ReleaseIDs, Notify),
		},
		"closed": {}, "retired": {},
	}
	for _, name := range []string{"pre", "candidate", "hook", "allocating", "waiting", "cea-write", "admission", "open", "closing-fence", "closing", "closed", "retired"} {
		for k := Start; k <= StopSupervision; k++ {
			t.Run(fmt.Sprintf("%s/input-%d", name, k), func(t *testing.T) {
				f := matrixSetup(t, name)
				in := matrixInput(t, name, k, f)
				want := rows[name][k]
				before := f.core.Snapshot()
				es := f.core.Handle(in)
				matrixPayloads(t, name, k, f, before, in, es)
				wantKinds(t, es, want.effects...)
				state := shapes[name]
				if want.next != "" {
					state = shapes[want.next]
				}
				if want.state != nil {
					state = *want.state
				}
				// Terminal snapshots retain whether the physical publication fence ran.
				if state.phase >= Closed {
					state.frozen = shapes[name].frozen
				}
				if got := shape(f.core); got != state {
					t.Fatalf("state=%+v want=%+v", got, state)
				}
				for _, e := range es {
					if e.Connection != connection {
						t.Fatal("effect escaped generation")
					}
					if (e.Kind == Send || e.Kind == ReserveIDs || e.Kind == ArmTimer || e.Kind == FreezeAdmission || e.Kind == ValidatedCER || e.Kind == HandshakeReady) && e.Token == 0 {
						t.Fatal("effect lacks completion token")
					}
				}
			})
		}
	}
}

func TestSnapshotStateDoesNotAlias(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	sent := grant(t, c, c.Handle(event(Start)))
	before := c.Snapshot()
	controls := before.Controls()
	controls[0].Logical = false
	if !reflect.DeepEqual(before.Controls(), c.Snapshot().Controls()) {
		t.Fatal("control snapshot shares slice")
	}
	c.Handle(complete(sent))
	c.Handle(event(Retire))
	if before.Phase() != WaitCEA || !before.Controls()[0].Logical {
		t.Fatal("snapshot changed after retirement")
	}
}

// matrixPayloads compares complete effects after resolving opaque operation
// tokens and builder-owned message internals. Wire bytes, snapshots, timer
// coordinates, dispositions and notification fields remain exact assertions.
func matrixPayloads(t testing.TB, name string, k InputKind, f matrixFixture, before Snapshot, in Input, es []Effect) {
	t.Helper()
	for i, e := range es {
		want := Effect{Kind: e.Kind, Connection: connection}
		want.ReleaseDispatch = i == 0 && k == Receive && (name == "open" || name == "closing")
		switch e.Kind {
		case ReserveIDs:
			want.Token = e.Token
			want.Command = diam.DisconnectPeer
			if name == "pre" || name == "allocating" {
				want.Command = diam.CapabilitiesExchange
			}
		case ReleaseIDs:
			controls := before.Controls()
			if len(controls) != 1 {
				t.Fatal("release lacks prior ownership")
			}
			want.Reservation = controls[0].Reservation
		case ArmTimer:
			want.Token = e.Token
			want.Timer = HandshakeTimer
			duration := f.core.cfg.HandshakeTimeout
			if k == Disconnect {
				want.Timer = ClosingTimer
				duration = f.core.cfg.ClosingTimeout
			}
			want.Deadline = in.At.Add(duration)
			if f.core.Snapshot().Timer(want.Timer) != (TimerSnapshot{want.Token, want.Deadline}) {
				t.Fatal("armed timer not installed")
			}
		case StopTimer:
			want.Timer = HandshakeTimer
			if name == "closing" || name == "closing-fence" {
				want.Timer = ClosingTimer
			}
			want.Token = before.Timer(want.Timer).Token
		case FreezeAdmission:
			want.Token = e.Token
		case CancelSend:
			want.Token = f.send.Token
		case Hold:
			want.Input = in
		case Admit:
			want.Message = in.Message
			want.Ownership = in.Ownership
		case ValidatedCER, Publish, HandshakeReady:
			want.Snapshot = f.core.Snapshot()
			want.Token = want.Snapshot.Admission()
			if e.Kind == ValidatedCER {
				want.Token = want.Snapshot.Candidate()
			}
		case CompleteRequest:
			want.Notification.Message = metadata(in.Message)
		case Send:
			want.Token = e.Token
			want.Stage = WrittenStage
			want.Required = true
			var message *diam.Message
			var err error
			switch k {
			case ReserveResult:
				message, err = base.BuildCER(f.core.cfg.Dictionary, f.core.cfg.Local)
				message.Header.HopByHopID = in.Reservation.Hop
				message.Header.EndToEndID = in.Reservation.End
				want.Required = false
			case Activate:
				message, err = base.BuildCEA(cer(t), f.core.cfg.Local, diam.Success)
			case Unhandled:
				want.Notification = Notification{Protocol: diam.ProtocolUnsupportedCommand, ResultCode: diam.CommandUnsupported, Message: metadata(in.Message)}
				message, err = base.BuildErrorAnswer(in.Message, f.core.cfg.Local, diam.CommandUnsupported, nil, true)
			default:
				message, err = base.BuildDWA(in.Message, f.core.cfg.Local)
				want.AnswerHook = true
			}
			if err != nil {
				t.Fatal(err)
			}
			gotBytes, err := e.Message.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, err := message.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotBytes, wantBytes) || e.Message.MessageStream() != message.MessageStream() {
				t.Fatal("send payload mismatch")
			}
			want.Message = e.Message // private dictionary/dispatch internals are opaque
		case Notify:
			switch {
			case k == Disconnect:
				want.Notification = Notification{Kind: DisconnectNotice, Outcome: NotOpen}
				if name == "closing" || name == "closing-fence" {
					want.Notification.Outcome = AlreadyPending
				}
			case k == ReleaseAdmission:
				want.Notification = Notification{Kind: HandshakeNotice}
			case k == Receive && name == "closing":
				want.Notification = Notification{Kind: DisconnectNotice, ResultCode: diam.Success}
			case e.Notification.Kind == HandshakeNotice || e.Notification.Kind == DisconnectNotice:
				want.Notification.Kind = HandshakeNotice
				if name == "closing" || name == "closing-fence" {
					want.Notification.Kind = DisconnectNotice
				}
				want.Notification.Outcome = ConnectionClosed
				if k == Abort {
					want.Notification.Outcome = Cancelled
				}
				if k == TimerExpired {
					want.Notification.Outcome = TimedOut
				}
			default:
				want.Notification.Message = metadata(in.Message)
				if k == TimerExpired {
					want.Notification.Protocol = diam.ProtocolHandshakeTimeout
					want.Notification.Closing = true
					if name == "closing" || name == "closing-fence" {
						want.Notification.Protocol = diam.ProtocolDisconnectTimeout
						want.Notification.Diagnostic = "local-disconnect"
						if name == "closing" {
							want.Message = f.send.Message
						}
					}
				} else {
					want.Notification.Protocol = diam.ProtocolHandshakeState
					want.Notification.Closing = true
					if name == "allocating" {
						want.Notification.Protocol = diam.ProtocolUnexpectedMessage
						want.Notification.Closing = false
					}
				}
			}
		}
		if !reflect.DeepEqual(e, want) {
			t.Fatalf("effect payload kind=%v got=%+v want=%+v", e.Kind, e, want)
		}
	}
}
