package peer

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// Keep event delivery synchronous so an extra notification cannot hide behind
// callback scheduling or a timeout in the sequence assertions.
func failureReportingActor(t *testing.T) (*actor, *session, *logtest.Recorder) {
	t.Helper()
	records := logtest.New()
	m := &Manager{cfg: Config{Settings: testSettings("local.example.net"), Logger: records.Logger(), Clock: &fakeClock{}, Timers: Timers{CER: time.Second, Closing: time.Second, TwInit: 6 * time.Second}}, callbackQ: make(chan PeerEvent, 32), controls: make(map[*session]map[uint32]struct{})}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: Closed, snapshotValue: fixtureHealth(WatchdogInitial), events: make(chan event, 64), done: make(chan struct{})}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a.publish(nil)
	t.Cleanup(s.close)
	return a, s, records
}

func assertFailureEvents(t *testing.T, a *actor, states []PeerState, watchdogs []WatchdogState, reasons []string) {
	t.Helper()
	if len(a.m.callbackQ) != len(states) {
		t.Fatalf("events=%d want %d", len(a.m.callbackQ), len(states))
	}
	for i, state := range states {
		e := <-a.m.callbackQ
		if e.Peer.State != state || e.Peer.Watchdog != watchdogs[i] || e.Peer.Eligible {
			t.Errorf("event %d snapshot=%+v", i, e.Peer)
		}
		if reasons[i] == "" {
			if e.Reason != nil {
				t.Errorf("event %d reason=%v", i, e.Reason)
			}
		} else if e.Reason == nil || !strings.Contains(e.Reason.Error(), reasons[i]) {
			t.Errorf("event %d reason=%v want %q", i, e.Reason, reasons[i])
		}
	}
}

func TestActorFailureEventSequences(t *testing.T) {
	t.Run("rejected CEA", func(t *testing.T) {
		a, s, _ := failureReportingActor(t)
		cer := reportingInitiator(t, a, s, true)
		cea, err := base.BuildCEA(cer, testBase("known.example.net"), diam.UnknownPeer)
		if err != nil {
			t.Fatal(err)
		}
		a.onWire(event{s: s, msg: cea})
		assertFailureEvents(t, a, []PeerState{Closed, Closed}, []WatchdogState{WatchdogInitial, WatchdogInitial}, []string{"", "invalid CEA"})
	})
	t.Run("open watchdog failure", func(t *testing.T) {
		a, s, _ := failureReportingActor(t)
		<-a.m.callbackQ
		a.state, a.i, a.active, a.everOpen = IOpen, s, s, true
		fixtureSetHealth(a, WatchdogSuspect)
		reportingOpen(t, s)
		a.publish(nil)
		<-a.m.callbackQ
		a.watchdogTick()
		assertFailureEvents(t, a, []PeerState{Closed, Closed}, []WatchdogState{WatchdogSuspect, WatchdogDown}, []string{"watchdog suspect timeout", "watchdog suspect timeout"})
	})
}

func assertFailureRecord(t *testing.T, records *logtest.Recorder, level slog.Level, message string, remote string, cause error) {
	t.Helper()
	got := records.Records()
	if len(got) != 1 {
		t.Fatalf("records=%d want 1: %v", len(got), got)
	}
	r := got[0]
	if r.Level != level || r.Message != message {
		t.Errorf("record=%s %q want %s %q", r.Level, r.Message, level, message)
	}
	if logtest.Attr(r, "peer_host").String() != "known.example.net" || logtest.Attr(r, "remote_addr").String() != remote {
		t.Errorf("attribution host=%q remote=%q", logtest.Attr(r, "peer_host"), logtest.Attr(r, "remote_addr"))
	}
	err, ok := logtest.Attr(r, "error").Any().(error)
	if !ok || cause != nil && !errors.Is(err, cause) {
		t.Errorf("error=%v want cause %v", err, cause)
	}
}

func TestActorFailureAttributionAndLevels(t *testing.T) {
	t.Run("without session", func(t *testing.T) {
		a, _, records := failureReportingActor(t)
		a.fail(errors.New("peer: state timeout"))
		assertFailureRecord(t, records, slog.LevelWarn, "peer: protocol error", "", nil)
	})
	t.Run("unbound candidate", func(t *testing.T) {
		a, s, records := failureReportingActor(t)
		s.actor = nil
		a.i = s
		a.fail(errors.New("peer: invalid CEA"))
		assertFailureRecord(t, records, slog.LevelWarn, "peer: protocol error", s.c.RemoteAddr().String(), nil)
	})
	t.Run("dial cause", func(t *testing.T) {
		a, _, records := failureReportingActor(t)
		a.state = WaitConnAck
		cause := errors.New("dial refused marker")
		a.onDial(event{err: cause})
		assertFailureRecord(t, records, slog.LevelError, "peer: dial failed; closing connection", "", cause)
		assertFailureEvents(t, a, []PeerState{Closed, Closed}, []WatchdogState{WatchdogInitial, WatchdogInitial}, []string{"", "dial refused marker"})
	})
	for _, operation := range []string{"CER", "CEA", "DWR", "DWA", "DPR"} {
		failures := []string{"send"}
		if operation == "CER" || operation == "CEA" {
			failures = append(failures, "build")
		}
		for _, failure := range failures {
			t.Run(operation+" "+failure, func(t *testing.T) {
				a, s, records := failureReportingActor(t)
				a.state, a.i, a.active = IOpen, s, s
				var cause error
				if failure == "build" {
					a.m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
				}
				var candidate *diam.Message
				switch operation {
				case "CER":
					s.inbound = false
					a.state = WaitConnAck
					if err := s.initProtocol(); err != nil {
						t.Fatal(err)
					}
				case "CEA":
					candidate = reportingCandidate(t, a, s)
				default:
					reportingOpen(t, s)
				}
				if failure == "send" {
					for len(s.writes) < cap(s.writes) {
						s.writes <- writeRequest{}
					}
					cause = errQueueFull
				} else {
					a.m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
				}
				req := watchdogRequest(t)
				switch operation {
				case "CER":
					a.state = WaitConnAck
					a.step(iAck, s, nil)
				case "CEA":
					s.cerRequest = candidate
					a.sendCEA(s)
				case "DWR":
					a.sendWatchdog()
				case "DWA":
					a.onWire(event{s: s, msg: req})
				case "DPR":
					a.step(stop, s, nil)
				}
				assertFailureRecord(t, records, slog.LevelError, "peer: "+failure+" "+operation+" failed; closing connection", s.c.RemoteAddr().String(), cause)
			})
		}
	}
}

func TestManagerLocalFailureLevels(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, operation := range []string{"DPA answer", "rejected CER answer", "build rejected CER answer", "unsupported answer", "error answer", "ingress", "message-error ingress", "write"} {
		t.Run(operation, func(t *testing.T) {
			a, s, records := failureReportingActor(t)
			a.state, a.i, a.active = IOpen, s, s
			if operation == "rejected CER answer" || operation == "build rejected CER answer" {
				if operation == "build rejected CER answer" {
					a.m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
				}
				reportingCandidate(t, a, s)
			} else {
				reportingOpen(t, s)
			}
			a.publish(nil)
			a.m.sessions = map[diam.Conn]*session{s.c: s}
			for len(s.writes) < cap(s.writes) {
				s.writes <- writeRequest{}
			}
			req := watchdogRequest(t)
			switch operation {
			case "DPA answer":
				dpr, err := base.BuildDPR(testDict, testBase("known.example.net"), 0)
				if err != nil {
					t.Fatal(err)
				}
				a.answerDPR(s, dpr)
			case "rejected CER answer":
				reportingRejectCandidate(s, s.cerRequest, diam.UnknownPeer, nil)
			case "build rejected CER answer":
				a.m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
				reportingRejectCandidate(s, s.cerRequest, diam.UnknownPeer, nil)
			case "unsupported answer":
				a.onWire(event{s: s, msg: diam.NewRequest(999, 0, testDict)})
			case "error answer":
				a.onWire(event{s: s, msg: req, messageErr: &diam.MessageError{ResultCode: diam.InvalidAVPValue}})
			case "ingress":
				a.m.ServeDIAM(s.c, req)
			case "message-error ingress":
				if err := a.m.HandleMessageError(s.c, req, &diam.MessageError{ResultCode: diam.InvalidAVPValue}); err != nil {
					t.Fatal(err)
				}
			case "write":
				for len(s.writes) > 0 {
					<-s.writes
				}
				s.c = &failingWriteConn{s.c.(*fakeConn)}
				s.writes <- writeRequest{msg: req}
				a.m.wg.Add(1)
				s.writer()
			}
			got := records.Records()
			if len(got) == 0 {
				t.Fatal("no failure record")
			}
			r := got[len(got)-1]
			if r.Level != slog.LevelError || r.Message == "peer: protocol error" {
				t.Errorf("local %s logged as %s %q", operation, r.Level, r.Message)
			}
			if logtest.Attr(r, "peer_host").String() != "known.example.net" || logtest.Attr(r, "remote_addr").String() != s.c.RemoteAddr().String() {
				t.Errorf("missing local failure attribution: %v", r)
			}
			if logtest.Attr(r, "error").Any() == nil {
				t.Error("lost failure cause")
			}
		})
	}
}

func TestActorLocalInvariantAndShutdownRecords(t *testing.T) {
	for _, kind := range []string{"missing responder", "missing CER", "shutdown"} {
		t.Run(kind, func(t *testing.T) {
			a, s, records := failureReportingActor(t)
			a.state, a.i = WaitICEA, s
			level, message := slog.LevelError, "peer: send CEA failed; closing connection"
			switch kind {
			case "missing responder":
				a.sendCEA(nil)
			case "missing CER":
				a.sendCEA(s)
			case "shutdown":
				a.stop(0)
				level, message = slog.LevelInfo, "peer: shutdown during handshake; closing connection"
			}
			assertFailureRecord(t, records, level, message, s.c.RemoteAddr().String(), nil)
		})
	}
}

func TestManagerSendAdmissionFailureRecord(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	records := logtest.New()
	m.cfg.Logger = records.Logger()
	a, s := actors[0], sessions[0]
	for len(s.writes) < cap(s.writes) {
		s.writes <- writeRequest{}
	}
	p := &pendingRequest{msg: outboundRequest("a.example.net", "example.net"), attempted: make(map[*actor]bool), entries: make(map[*session]pendingAttempt), result: make(chan sendResult, 1)}
	if err := m.reserveAndSend(p, a, s, false); err != nil {
		t.Fatal(err)
	}
	got := records.Records()
	if len(got) != 1 {
		t.Fatalf("records=%v", got)
	}
	r := got[0]
	if r.Level != slog.LevelError || r.Message != "peer: send admission failed; closing connection" || !errors.Is(logtest.Attr(r, "error").Any().(error), errQueueFull) {
		t.Fatalf("record=%v", r)
	}
	if logtest.Attr(r, "peer_host").String() != "a.example.net" || logtest.Attr(r, "remote_addr").String() != s.c.RemoteAddr().String() {
		t.Fatalf("attribution=%v", r)
	}
}

func TestSessionDispatchLocalFailureRecord(t *testing.T) {
	_, s, records := failureReportingActor(t)
	reportingOpen(t, s)
	s.actor = nil
	s.ingress = make(chan incoming, 1)
	s.ingress <- incoming{msg: watchdogRequest(t), err: &diam.MessageError{ResultCode: diam.InvalidAVPValue}}
	for len(s.writes) < cap(s.writes) {
		s.writes <- writeRequest{}
	}
	s.m.wg.Add(1)
	s.dispatch()
	got := records.Records()
	if len(got) != 1 {
		t.Fatalf("records=%v", got)
	}
	r := got[0]
	if r.Level != slog.LevelError || r.Message != "peer: error answer failed; closing connection" || !errors.Is(logtest.Attr(r, "error").Any().(error), errQueueFull) {
		t.Fatalf("record=%v", r)
	}
	if logtest.Attr(r, "peer_host").String() != "" || logtest.Attr(r, "remote_addr").String() != s.c.RemoteAddr().String() {
		t.Fatalf("attribution=%v", r)
	}
}

func TestActorFailureStopsTransitionPublication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   PeerState
		trigger psmEvent
	}{
		{"responder CER", Closed, rConnCER},
		{"election dial failed", WaitConnAckElect, iNack},
		{"election won", WaitReturns, winElection},
		{"initiator disconnected", WaitReturns, iDisc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _ := failureReportingActor(t)
			request := reportingCandidate(t, a, s)
			a.state, a.r = tc.state, s
			s.cerRequest = request
			for len(s.writes) < cap(s.writes) {
				s.writes <- writeRequest{}
			}
			if tc.trigger == iNack {
				a.onDial(event{err: errors.New("dial marker")})
			} else {
				a.step(tc.trigger, s, s.cerRequest)
			}
			assertFailureEvents(t, a, []PeerState{Closed, Closed}, []WatchdogState{WatchdogInitial, WatchdogInitial}, []string{"", "send CEA"})
		})
	}
	t.Run("reopen watchdog", func(t *testing.T) {
		a, s, _ := failureReportingActor(t)
		<-a.m.callbackQ
		a.everOpen = true
		fixtureSetHealth(a, WatchdogDown)
		a.publish(nil)
		cer := reportingInitiator(t, a, s, true)
		for len(a.m.callbackQ) > 0 {
			<-a.m.callbackQ
		}
		for len(s.writes) < cap(s.writes) {
			s.writes <- writeRequest{}
		}
		cea := correlationCEA(t, cer, "known.example.net")
		a.onWire(event{s: s, msg: cea})
		assertFailureEvents(t, a, []PeerState{IOpen, Closed, Closed}, []WatchdogState{WatchdogReopen, WatchdogReopen, WatchdogDown}, []string{"recovered connection", "send DWR", "send DWR"})
	})
}

func TestActorRefusedDialRecord(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	c, dialErr := net.DialTimeout("tcp", address, time.Second)
	if dialErr == nil {
		_ = c.Close()
		t.Fatal("dial unexpectedly succeeded")
	}
	var original *net.OpError
	if !errors.As(dialErr, &original) || original.Addr == nil {
		t.Fatalf("dial error=%v", dialErr)
	}
	a, _, records := failureReportingActor(t)
	a.state = WaitConnAck
	a.onDial(event{err: dialErr})
	assertFailureRecord(t, records, slog.LevelError, "peer: dial failed; closing connection", address, dialErr)
	var retained *net.OpError
	if !errors.As(logtest.Attr(records.Records()[0], "error").Any().(error), &retained) || retained != original {
		t.Fatalf("lost network error: %v", retained)
	}
}

func TestActorFailedDialUsesFailedEndpointDuringElection(t *testing.T) {
	a, s, records := failureReportingActor(t)
	s.cerRequest = reportingCandidate(t, a, s)
	a.state, a.r = WaitConnAckElect, s
	destination := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 40), Port: 3868}
	cause := &net.OpError{Op: "dial", Net: "tcp", Addr: destination, Err: errors.New("refused marker")}
	a.onDial(event{err: cause})
	assertFailureRecord(t, records, slog.LevelError, "peer: dial failed", destination.String(), cause)
	if a.state != ROpen || a.active != s {
		t.Fatalf("responder did not survive failed dial: state=%s active=%p", a.state, a.active)
	}
	select {
	case <-s.closed:
		t.Fatal("surviving responder was closed")
	default:
	}
}
