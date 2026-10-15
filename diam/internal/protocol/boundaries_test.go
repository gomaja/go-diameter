package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// #108/#128: handshake callback cannot precede the CEA send boundary.
func TestAdmissionReleaseRequiresReady(t *testing.T) {
	c := machine(t)
	es := accept(t, c)
	publish := find(t, es, Publish)
	in := event(ReleaseAdmission)
	in.Token = publish.Token
	wantKinds(t, c.Handle(in))
	if c.Snapshot().Ready() {
		t.Fatal("released before CEA completion")
	}
}

// #108: pre-admitted DWR work can finish while Closing; its hook must not
// prevent a later DPR from publishing Closing in arrival order.
func TestDWRHookDoesNotBlockClosing(t *testing.T) {
	c := opened(t)
	c.cfg.Hooks = true
	hook := find(t, c.Handle(receive(request(t, diam.DeviceWatchdog))), RunHook)
	es := c.Handle(receive(request(t, diam.DisconnectPeer)))
	find(t, es, FreezeAdmission)
	in := event(Continue)
	in.Token = hook.Token
	es = c.Handle(in)
	find(t, es, Send)
	if c.Snapshot().Phase() != Closing {
		t.Fatal("hook continuation reopened generation")
	}
}

// RFC 6733 §§5.3,5.4,5.6; #108: complete control waiters once on retirement,
// including before allocation and while a selected writer is still blocked.
func TestControlWaitersCompleteOnce(t *testing.T) {
	for _, kind := range []InputKind{Abort, TransportLost, Retire} {
		c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
		reserve := find(t, c.Handle(event(Start)), ReserveIDs)
		es := c.Handle(event(kind))
		n := find(t, es, Notify)
		if n.Notification.Kind != HandshakeNotice || n.Notification.Outcome == Completed {
			t.Fatal("handshake waiter not failed")
		}
		wantKinds(t, c.Handle(event(kind)))
		late := event(ReserveResult)
		late.Token = reserve.Token
		late.Reservation = Reservation{Token: 123}
		wantKinds(t, c.Handle(late), ReleaseIDs)
	}
	c := opened(t)
	local := event(Disconnect)
	grant(t, c, fence(t, c, local, false))
	es := c.Handle(event(Retire))
	n := find(t, es, Notify)
	if n.Notification.Kind != DisconnectNotice || n.Notification.Outcome != ConnectionClosed {
		t.Fatal("disconnect waiter not failed")
	}
	wantKinds(t, c.Handle(event(Retire)))
}

func TestConfigAndDetachedSnapshots(t *testing.T) {
	for _, edit := range []func(*Config){
		func(c *Config) { c.Connection.Instance = 0 }, func(c *Config) { c.Role = 99 },
		func(c *Config) { c.HandshakeTimeout = -1 }, func(c *Config) { c.CERInterval = -1 }, func(c *Config) { c.ClosingTimeout = -1 },
		func(c *Config) { c.Watchdog = true; c.WatchdogInterval = time.Second },
		func(c *Config) {
			c.Local.ResolveHostIPAddresses = func() ([]datatype.Address, error) { t.Fatal("resolver invoked"); return nil, nil }
		},
		func(c *Config) { c.Local.AuthApplicationID = []*diam.AVP{nil} },
	} {
		cfg := configuration(t)
		edit(&cfg)
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	cfg := configuration(t)
	cfg.Dictionary = nil
	cfg.Local.Applications = []base.LocalApplication{{ID: 4, SupportedVendors: []uint32{1}}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Connection() != connection || s.Role() != Responder || s.Admission() != 0 || s.Timer(99) != (TimerSnapshot{}) {
		t.Fatal("initial snapshot")
	}
	cfg.Local.Applications[0].SupportedVendors[0] = 9
	if c.Snapshot().Capabilities().Local.Applications[0].SupportedVendors[0] != 1 {
		t.Fatal("nested local config alias")
	}
	if !reflect.DeepEqual(copyMessage(nil), (*diam.Message)(nil)) {
		t.Fatal("nil copy")
	}
}

// RFC 6733 §§5.3,6.10 and #108: all capability failures retain base builders.
func TestCERRejectionsAndBuildFailure(t *testing.T) {
	for _, variant := range []string{"no-common-app", "no-common-security", "expected-host", "bad-hook-body", "no-address", "unknown-peer"} {
		t.Run(variant, func(t *testing.T) {
			c := machine(t)
			m := cer(t)
			switch variant {
			case "no-common-app":
				for _, a := range m.AVP {
					if a.Code == 258 {
						a.Data = datatype.Unsigned32(99)
					}
				}
			case "no-common-security":
				m.AddAVP(diam.NewAVP(299, 64, 0, datatype.Unsigned32(1)))
			case "expected-host":
				c.cfg.ExpectedHost = "other.example"
			case "bad-hook-body":
				c.cfg.Hooks = true
			case "no-address":
				c.cfg.Local.HostIPAddresses = nil
			}
			es := c.Handle(receive(m))
			if variant == "bad-hook-body" {
				hook := find(t, es, RunHook)
				in := event(Continue)
				in.Token = hook.Token
				in.Message = copyMessage(m)
				in.Message.AVP = nil
				es = c.Handle(in)
			}
			if variant == "no-address" {
				candidate := find(t, es, ValidatedCER)
				in := event(Activate)
				in.Token = candidate.Token
				find(t, c.Handle(in), Close)
				return
			}
			if variant == "unknown-peer" {
				candidate := find(t, es, ValidatedCER)
				in := event(RejectCandidate)
				in.Token = candidate.Token
				in.ResultCode = diam.UnknownPeer
				es = c.Handle(in)
			}
			sent := find(t, es, Send)
			if resultCode(t, sent.Message) == diam.Success {
				t.Fatal("rejection reported success")
			}
			find(t, c.Handle(complete(sent)), Close)
		})
	}
}

// RFC 6733 §§3,4.1,7.1.5/7.2/7.5, Verified Errata 4615/4887; #108/#127.
func TestValidationAndErrorEvidence(t *testing.T) {
	for _, variant := range []string{"header", "missing", "decode", "fatal", "answer", "closing-decode", "mandatory", "unsupported-app", "request-grammar"} {
		t.Run(variant, func(t *testing.T) {
			c := opened(t)
			m := request(t, diam.DeviceWatchdog)
			in := receive(m)
			switch variant {
			case "header":
				m.Header.ApplicationID = 1
			case "missing":
				m.AVP = nil
			case "decode":
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue, FailedAVP: diam.NewAVP(264, 64, 0, datatype.OctetString("bad"))}
			case "fatal":
				in.Error = &diam.MessageError{Fatal: true, ResultCode: diam.InvalidMessageLength}
			case "answer":
				m.Header.CommandFlags = 0
				m.AVP = nil
			case "closing-decode":
				fence(t, c, receive(request(t, diam.DisconnectPeer)), false)
				in = receive(request(t, diam.DisconnectPeer))
				in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue}
			case "mandatory":
				c.cfg.RejectUnknownMandatoryAVPs = true
				m.AddAVP(diam.NewAVP(999999, 64, 0, datatype.OctetString("x")))
				c.cfg.Dictionary.SetStrict(false)
				raw, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := diam.ReadMessage(bytes.NewReader(raw), c.cfg.Dictionary)
				if err != nil {
					t.Fatal(err)
				}
				in.Message = decoded
			case "unsupported-app":
				c.cfg.ValidateRequests = true
				in.Message = diam.NewRequest(999, 8, c.cfg.Dictionary)
			case "request-grammar":
				c.cfg.ValidateRequests = true
				in.Message = diam.NewRequest(275, 0, c.cfg.Dictionary)
			}
			es := c.Handle(in)
			if variant == "answer" || variant == "closing-decode" {
				wantKinds(t, es, Discard, Notify)
				return
			}
			sent := find(t, es, Send)
			if resultCode(t, sent.Message) == diam.Success {
				t.Fatal("invalid request answered success")
			}
			failed, err := sent.Message.FindAVPs(279, 0)
			if variant == "missing" || variant == "decode" || variant == "mandatory" {
				if err != nil || len(failed) != 1 {
					t.Fatalf("Failed-AVP count=%d err=%v", len(failed), err)
				}
			}
			if sent.Message.Header.HopByHopID != in.Message.Header.HopByHopID || sent.Message.Header.EndToEndID != in.Message.Header.EndToEndID {
				t.Fatal("error IDs changed")
			}
			for _, code := range []uint32{264, 296} {
				if _, err := sent.Message.FindAVP(code, 0); err != nil {
					t.Fatal("missing local answer identity")
				}
			}
		})
	}
}

func TestIdentityBindingAndLateInputs(t *testing.T) {
	c := opened(t)
	m := request(t, diam.DeviceWatchdog)
	m.AVP[0].Data = datatype.DiameterIdentity("REMOTE.EXAMPLE")
	find(t, c.Handle(receive(m)), Send)
	m = request(t, diam.DeviceWatchdog)
	m.AVP[0].Data = datatype.DiameterIdentity("x")
	wantKinds(t, c.Handle(receive(m)), Discard, Notify)
	m = request(t, diam.DisconnectPeer)
	m.AVP[0].Data = datatype.DiameterIdentity("other.example")
	wantKinds(t, c.Handle(receive(m)), Discard, Notify)
	m = cer(t)
	m.AVP = nil
	wantKinds(t, c.Handle(receive(m)), Discard, Notify)
	in := event(Continue)
	in.Token = 999
	wantKinds(t, c.Handle(in))
	in = event(Frozen)
	in.Token = 999
	wantKinds(t, c.Handle(in))
	in = event(Disconnect)
	in.Cause = 3
	wantKinds(t, c.Handle(in), Notify)
	in.Cause = 0
	fence(t, c, in, false)
	wantKinds(t, c.Handle(in), Notify)
	wantKinds(t, c.Handle(receive(nil)), Discard)
}

func TestExecutorDoesNotHoldMutationLockOverEffects(t *testing.T) {
	c := machine(t)
	sent := find(t, accept(t, c), Send)
	var mu sync.Mutex
	blocked := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		<-blocked
		mu.Lock()
		c.Handle(complete(sent))
		mu.Unlock()
		close(done)
	}()
	<-started
	mu.Lock()
	c.Handle(event(Retire))
	mu.Unlock()
	close(blocked)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retirement joined blocked effect")
	}
	if c.Snapshot().Phase() != Retired {
		t.Fatal("late write revived core")
	}
}

func TestBuildAndQueueBoundaryFailures(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator; cfg.Local.HostIPAddresses = nil })
	reserve := find(t, c.Handle(event(Start)), ReserveIDs)
	in := event(ReserveResult)
	in.Token = reserve.Token
	in.Reservation = Reservation{Token: 123}
	es := c.Handle(in)
	find(t, es, ReleaseIDs)
	find(t, es, Close)
	c = opened(t)
	sent := find(t, c.Handle(receive(request(t, diam.DeviceWatchdog))), Send)
	ack := complete(sent)
	ack.Stage = QueueStage
	wantKinds(t, c.Handle(ack))
	wantKinds(t, c.Handle(ack))
	ack.Stage = WrittenStage
	ack.ExpectedBytes = 0
	wantKinds(t, c.Handle(ack))
	c = machine(t, func(cfg *Config) { cfg.Role = Initiator })
	reserve = find(t, c.Handle(event(Start)), ReserveIDs)
	c.Handle(event(Retire))
	in = event(ReserveResult)
	in.Token = reserve.Token
	in.Err = errors.New("allocation cancelled")
	wantKinds(t, c.Handle(in))
}

// RFC 6733 §5.6 Wait-I-CEA; #108: a dialed generation cannot accept a CER,
// including the interval before the local CER allocator completes.
func TestInitiatorCannotAcceptCERBeforeStart(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	es := c.Handle(receive(cer(t)))
	find(t, es, Close)
	if c.Snapshot().Candidate() != 0 || c.Snapshot().Phase() != Closed {
		t.Fatal("initiator became responder")
	}
}

// #108 required reply failures: all stages retain the triggering request's
// immutable metadata, including successful replies with no normal diagnostic.
func TestRequiredReplyFailureEvidence(t *testing.T) {
	for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(fmt.Sprint(command), func(t *testing.T) {
			c := machine(t)
			var sent Effect
			var original *diam.Message
			if command == diam.CapabilitiesExchange {
				original = cer(t)
				candidate := find(t, c.Handle(receive(original)), ValidatedCER)
				in := event(Activate)
				in.Token = candidate.Token
				sent = find(t, c.Handle(in), Send)
			} else {
				c = opened(t)
				original = request(t, command)
				if command == diam.DisconnectPeer {
					sent = find(t, fence(t, c, receive(original), false), Send)
				} else {
					sent = find(t, c.Handle(receive(original)), Send)
				}
			}
			in := complete(sent)
			in.Err = errors.New("write failed")
			in.ReplyCode = diam.Success
			es := c.Handle(in)
			var failure *Notification
			for _, e := range es {
				if e.Kind == Notify && e.Notification.Protocol == diam.ProtocolReplyFailure {
					n := e.Notification
					failure = &n
				}
			}
			if failure == nil || failure.Message != metadata(original) || failure.Reply != diam.ProtocolReplyFailed || failure.ReplyCode != diam.Success {
				t.Fatalf("failure=%+v want metadata=%+v", failure, metadata(original))
			}
		})
	}
	c := machine(t)
	candidate := find(t, c.Handle(receive(cer(t))), ValidatedCER)
	c.cfg.Local.HostIPAddresses = nil
	in := event(Activate)
	in.Token = candidate.Token
	es := c.Handle(in)
	var failure *Notification
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Protocol == diam.ProtocolReplyFailure {
			n := e.Notification
			failure = &n
		}
	}
	if failure == nil || failure.Reply != diam.ProtocolReplyFailed || failure.ReplyCode != diam.Success || !failure.Message.HasHeader {
		t.Fatalf("build failure=%+v", failure)
	}
}

func TestUnknownWriteStageIsInert(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.QueueWrites = true })
	sent := find(t, accept(t, c), Send)
	in := complete(sent)
	in.Stage = 99
	wantKinds(t, c.Handle(in))
	if c.callbackReady {
		t.Fatal("invalid stage published readiness")
	}
	find(t, c.Handle(complete(sent)), HandshakeReady)
}
