package peer

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func reportingOpen(t *testing.T, s *session) {
	t.Helper()
	if err := bootstrapSessionProtocol(s); err != nil {
		t.Fatal(err)
	}
}

// Real initiator startup reserves its CER coordinates before the fixture
// supplies a CEA. It leaves the selected CER queued for failure injection when
// publish is false, and otherwise completes that writer before returning.
func reportingInitiator(t *testing.T, a *actor, s *session, publish bool) *diam.Message {
	t.Helper()
	s.inbound = false
	a.state, a.i, a.r, a.active = WaitICEA, s, nil, nil
	if a.events == nil {
		a.events = make(chan event, 64)
	}
	if a.done == nil {
		a.done = make(chan struct{})
	}
	if err := s.initProtocol(); err != nil {
		t.Fatal(err)
	}
	s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
	if !publish {
		return nil
	}
	w := requiredQueuedWrite(t, s)
	if w.msg.Header.CommandCode != diam.CapabilitiesExchange || w.msg.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("startup selected %+v", w.msg.Header)
	}
	fixtureCompleteWrite(s, w)
	return w.msg
}

func reportingResponder(t *testing.T, a *actor, s *session) {
	t.Helper()
	s.inbound = true
	a.state, a.r, a.i, a.active = Closed, nil, nil, nil
	if a.events == nil {
		a.events = make(chan event, 64)
	}
	if a.done == nil {
		a.done = make(chan struct{})
	}
	if err := s.initProtocol(); err != nil {
		t.Fatal(err)
	}
	s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
}

// Holding the responder in the actor's election state produces a validated
// candidate without selecting CEA, exactly as concurrent dialing does.
func reportingCandidate(t *testing.T, a *actor, s *session) *diam.Message {
	t.Helper()
	reportingResponder(t, a, s)
	a.state = WaitConnAck
	request, err := base.BuildCER(s.m.dictionary(), testBase(string(a.cfg.Host)))
	if err != nil {
		t.Fatal(err)
	}
	a.onWire(event{s: s, msg: request})
	// Before the first CER, this session has no actor responder slot.
	if s.candidate == 0 {
		s.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: request}, nil)
	}
	if s.candidate == 0 || len(s.writes) != 0 {
		t.Fatalf("election failed to hold validated CER: candidate=%d writes=%d", s.candidate, len(s.writes))
	}
	return request
}

func reportingWriteOne(t *testing.T, s *session, w writeRequest) bool {
	t.Helper()
	stopped := s.writeOne(w)
	if s.actor != nil {
		for len(s.actor.events) > 0 {
			s.actor.handle(<-s.actor.events)
		}
	}
	return stopped || s.c.Closed()
}

// The normal actor runner supplies serialization and the separate observer
// boundary used by concurrent writer/callback tests.
func reportingStartActor(t *testing.T, a *actor) {
	t.Helper()
	m := a.m
	m.mu.Lock()
	m.peers[identity(a.cfg.Host)] = a
	m.wg.Add(1)
	m.mu.Unlock()
	go a.run()
	t.Cleanup(func() {
		if a.activeSession.Load() != nil {
			a.post(event{kind: connGone, s: a.activeSession.Load()})
		}
		closeManager(t, m, nil)
	})
}

func reportingReceive(a *actor, s *session, msg *diam.Message, d *protocolDelivery) {
	owned := d == nil
	if owned {
		d = newProtocolDelivery()
	}
	a.commit(event{kind: wireEvent, s: s, msg: msg}, d)
	if owned {
		d.deliver(s.m)
	}
}

func reportingRejectCandidate(s *session, msg *diam.Message, code uint32, d *protocolDelivery) {
	s.applyProtocol(protocol.Input{Kind: protocol.RejectCandidate, Token: s.candidate, Message: msg, ResultCode: code}, d)
}

func newReportingRawActor(t *testing.T) (*actor, *session, *fakeClock) {
	t.Helper()
	clock := &fakeClock{}
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: Closed, watchdog: WatchdogInitial, events: make(chan event, 64), done: make(chan struct{})}
	s := &session{m: m, c: newFakeConn(), actor: a, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a.publish(nil)
	t.Cleanup(func() { s.close(); closeManager(t, m, nil) })
	return a, s, clock
}

func reportingExpire(s *session, kind protocol.TimerKind) {
	timer := s.protocolSnapshot().Timer(kind)
	s.applyProtocol(protocol.Input{Kind: protocol.TimerExpired, Timer: kind, Token: timer.Token, At: timer.Deadline}, nil)
}

// A writer's return precedes its actor completion and observer delivery. Wait
// for the production reply-ordering slot to contain that completion before
// asserting the admission observer still owns delivery.
func reportingAwaitReplyFailure(t *testing.T, d *protocolDelivery) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		d.replyMu.Lock()
		ready := d.failedReply != nil
		d.replyMu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("writer completion did not reach the admission delivery slot")
		}
		time.Sleep(time.Millisecond)
	}
}
