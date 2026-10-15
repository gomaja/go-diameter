package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func find(t testing.TB, es []Effect, k EffectKind) Effect {
	t.Helper()
	for _, e := range es {
		if e.Kind == k {
			return e
		}
	}
	t.Fatalf("missing effect %v in %v", k, kinds(es))
	return Effect{}
}
func remote(t testing.TB) Config {
	t.Helper()
	cfg := configuration(t)
	cfg.Local.OriginHost = "remote.example"
	return cfg
}
func cer(t testing.TB) *diam.Message {
	t.Helper()
	cfg := remote(t)
	m, err := base.BuildCER(cfg.Dictionary, cfg.Local)
	if err != nil {
		t.Fatal(err)
	}
	m.Header.HopByHopID = 10
	m.Header.EndToEndID = 20
	return m
}
func receive(m *diam.Message) Input { in := event(Receive); in.Message = m; return in }
func complete(e Effect) Input {
	in := event(WriteResult)
	in.Token = e.Token
	in.Stage = WrittenStage
	in.Bytes = int64(e.Message.Len())
	in.ExpectedBytes = in.Bytes
	return in
}
func accept(t testing.TB, c *Core) []Effect {
	t.Helper()
	c.Handle(event(Start))
	candidate := find(t, c.Handle(receive(cer(t))), ValidatedCER)
	in := event(Activate)
	in.Token = candidate.Token
	return c.Handle(in)
}
func opened(t testing.TB, edit ...func(*Config)) *Core {
	t.Helper()
	c := machine(t, edit...)
	sent := find(t, accept(t, c), Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	in := event(ReleaseAdmission)
	in.Token = ready.Token
	c.Handle(in)
	return c
}
func grant(t testing.TB, c *Core, es []Effect) Effect {
	t.Helper()
	e := find(t, es, ReserveIDs)
	in := event(ReserveResult)
	in.Token = e.Token
	in.Reservation = Reservation{Token: 100 + e.Token, Hop: 30, End: 40}
	return find(t, c.Handle(in), Send)
}

// RFC 6733 §§5.3,5.6.1,5.6.4; #108: election holds a validated CER,
// successful metadata precedes CEA, and OnHandshake remains an admission barrier.
func TestCandidateActivationAndBarrier(t *testing.T) {
	c := machine(t)
	c.Handle(event(Start))
	es := c.Handle(receive(cer(t)))
	wantKinds(t, es, ValidatedCER)
	candidate := es[0]
	if c.Snapshot().Phase() != PreCER || c.Snapshot().Ready() {
		t.Fatal("candidate admitted prematurely")
	}
	in := event(Activate)
	in.Token = candidate.Token + 1
	wantKinds(t, c.Handle(in))
	in.Token = candidate.Token
	es = c.Handle(in)
	wantKinds(t, es, StopTimer, Publish, Send)
	if c.Snapshot().Phase() != Open || c.Snapshot().Ready() {
		t.Fatal("activation barrier")
	}
	// A second activation cannot publish a second CEA.
	wantKinds(t, c.Handle(in))
	app := diam.NewRequest(999, 4, c.cfg.Dictionary)
	wantKinds(t, c.Handle(receive(app)), Hold)
	sent := find(t, es, Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	release := event(ReleaseAdmission)
	release.Token = ready.Token
	wantKinds(t, c.Handle(release), Notify)
	wantKinds(t, c.Handle(receive(app)), Admit)
	wantKinds(t, c.Handle(release))
}

func TestCandidateDelayAndPreHook(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Hooks = true })
	in := receive(cer(t))
	hook := find(t, c.Handle(in), RunHook)
	wantKinds(t, c.Handle(receive(cer(t))), Hold)
	cont := event(Continue)
	cont.Token = hook.Token
	cont.TransportClosed = true
	wantKinds(t, c.Handle(cont), Close)
	if c.Snapshot().Candidate() != 0 {
		t.Fatal("hook-close created candidate")
	}
	c = machine(t)
	candidate := find(t, c.Handle(in), ValidatedCER)
	reject := event(RejectCandidate)
	reject.Token = candidate.Token
	wantKinds(t, c.Handle(reject), Close)
	activate := event(Activate)
	activate.Token = candidate.Token
	wantKinds(t, c.Handle(activate))
}

// RFC 6733 §§3,5.3.2,6.2.1; #108: unrelated CEA must retain the deadline.
func TestWaitCEACorrelation(t *testing.T) {
	for _, field := range []string{"hop", "end", "generation", "instance"} {
		t.Run(field, func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
			sent := grant(t, c, c.Handle(event(Start)))
			c.Handle(complete(sent))
			answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			in := receive(answer)
			switch field {
			case "hop":
				answer.Header.HopByHopID++
			case "end":
				answer.Header.EndToEndID++
			case "generation":
				in.Connection.Generation++
			case "instance":
				in.Connection.Instance++
			}
			before := c.Snapshot().Timer(HandshakeTimer)
			es := c.Handle(in)
			if field == "hop" || field == "end" {
				wantKinds(t, es, Discard, Notify)
			} else {
				wantKinds(t, es)
			}
			if c.Snapshot().Phase() != WaitCEA || c.Snapshot().Timer(HandshakeTimer) != before {
				t.Fatal("stray answer consumed admission/deadline")
			}
		})
	}
}

func TestEarlyCEAAndReservationPin(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	sent := grant(t, c, c.Handle(event(Start)))
	answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	es := c.Handle(receive(answer))
	wantKinds(t, es, CompleteRequest, StopTimer, Publish, HandshakeReady)
	if len(c.Snapshot().Controls()) != 1 {
		t.Fatal("early CEA released selected writer ID")
	}
	es = c.Handle(complete(sent))
	wantKinds(t, es, ReleaseIDs)
	if c.Snapshot().Phase() != Open {
		t.Fatal("late write resurrected handshake")
	}
}

// RFC 6733 §§5.3.2,5.6; #108: each CEA rejection is independent of
// configured-host rejection and retains its exact handshake completion.
func TestExpectedHostAndMalformedCEA(t *testing.T) {
	for _, variant := range []string{"host", "body", "fatal", "non-cea", "failure", "success"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.ExpectedHost = "remote.example" })
			sent := grant(t, c, c.Handle(event(Start)))
			c.Handle(complete(sent))
			answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
			if err != nil {
				t.Fatal(err)
			}
			in := receive(answer)
			kind, code := diam.ProtocolCEARejected, uint32(0)
			switch variant {
			case "host":
				c.cfg.ExpectedHost = "expected.example"
			case "body":
				answer.AVP = nil
				kind, code = diam.ProtocolCEARejected, diam.MissingAVP
			case "fatal":
				in.Error = &diam.MessageError{Fatal: true, ResultCode: diam.InvalidMessageLength}
				code = diam.InvalidMessageLength
			case "non-cea":
				in.Message = cer(t)
				kind = diam.ProtocolHandshakeState
			case "failure":
				answer, err = base.BuildCEA(sent.Message, remote(t).Local, diam.UnableToComply)
				if err != nil {
					t.Fatal(err)
				}
				in.Message = answer
				code = diam.UnableToComply
			}
			es := c.Handle(in)
			if variant == "success" {
				wantKinds(t, es, CompleteRequest, ReleaseIDs, StopTimer, Publish, HandshakeReady)
				ready := find(t, es, HandshakeReady).Snapshot
				if ready.Phase() != Open || ready.Handshake().Err() != nil || ready.Handshake().CEA().ResultCode != diam.Success {
					t.Fatalf("successful CEA: %+v", ready)
				}
				return
			}
			find(t, es, Close)
			if c.Snapshot().Phase() != Closed {
				t.Fatal("invalid CEA opened")
			}
			var rejection Notification
			for _, e := range es {
				if e.Kind == Notify && e.Notification.Kind == ProtocolNotice {
					rejection = e.Notification
				}
			}
			if rejection.Protocol != kind || rejection.ResultCode != code || !rejection.Closing {
				t.Fatalf("rejection=%+v want=%v/%d", rejection, kind, code)
			}
			completion := handshakeCompletion(t, es)
			if completion.Outcome != ConnectionClosed {
				t.Fatalf("completion=%+v", completion)
			}
			if variant == "host" && !errors.Is(completion.Handshake.Err(), ErrUnexpectedPeer) {
				t.Fatalf("host error=%v", completion.Handshake.Err())
			}
			if variant == "failure" {
				var failed *base.ErrFailedResultCode
				if !errors.As(completion.Handshake.Err(), &failed) || failed.ResultCode != diam.UnableToComply || completion.Handshake.CEA().OriginHost != "remote.example" {
					t.Fatalf("failure=%+v", completion)
				}
			}
		})
	}
}

// RFC 6733 §5.3; #108: metadata and advertised capabilities are stable snapshots.
func TestSnapshotIsolation(t *testing.T) {
	cfg := configuration(t)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Local.AuthApplicationID[0].Data = datatype.Unsigned32(999)
	es := c.Handle(receive(cer(t)))
	candidate := find(t, es, ValidatedCER)
	caps := candidate.Snapshot.Capabilities()
	caps.Local.AuthApplicationID[0].Data = datatype.Unsigned32(100)
	caps.CER.OriginHost = "changed.example"
	caps.RemoteApplications[0] = 999
	in := event(Activate)
	in.Token = candidate.Token
	c.Handle(in)
	s := c.Snapshot()
	copy := s.Capabilities()
	copy.LocalApplications[0] = 8
	if s.Capabilities().Host != "remote.example" || c.Snapshot().Capabilities().LocalApplications[0] != 4 || c.Snapshot().Capabilities().RemoteApplications[0] != 4 {
		t.Fatal("mutable snapshot alias")
	}
}

func TestCERTimeoutAndRetryBudget(t *testing.T) {
	c := machine(t, func(cfg *Config) {
		cfg.Role = Initiator
		cfg.HandshakeTimeout = 0
		cfg.CERInterval = time.Second
		cfg.MaxRetransmits = 1
	})
	sent := grant(t, c, c.Handle(event(Start)))
	es := c.Handle(complete(sent))
	timer := find(t, es, ArmTimer)
	expiry := event(TimerExpired)
	expiry.Timer = RetryTimer
	expiry.Token = timer.Token
	expiry.At = timer.Deadline
	es = c.Handle(expiry)
	retry := find(t, es, Send)
	if retry.Message.Header.HopByHopID != sent.Message.Header.HopByHopID || retry.Message.Header.EndToEndID != sent.Message.Header.EndToEndID {
		t.Fatal("retry changed identifiers")
	}
	done := complete(retry)
	done.At = expiry.At
	timer = find(t, c.Handle(done), ArmTimer)
	expiry.Token = timer.Token
	expiry.At = timer.Deadline
	es = c.Handle(expiry)
	find(t, es, Close)
	if c.Snapshot().Phase() != Closed {
		t.Fatal("retry budget exceeded")
	}
}

func TestReservationFailureAndLateGrant(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	reserve := find(t, c.Handle(event(Start)), ReserveIDs)
	c.Handle(event(Retire))
	in := event(ReserveResult)
	in.Token = reserve.Token
	in.Reservation = Reservation{Token: 123}
	wantKinds(t, c.Handle(in), ReleaseIDs)
	wantKinds(t, c.Handle(in))
	c = machine(t, func(cfg *Config) { cfg.Role = Initiator })
	reserve = find(t, c.Handle(event(Start)), ReserveIDs)
	in = event(ReserveResult)
	in.Token = reserve.Token
	in.Err = errors.New("exhausted")
	find(t, c.Handle(in), Close)
}
