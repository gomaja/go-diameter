package peer

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestSessionCommitsInitiatorStartupBeforeRegistration(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net"}, events: make(chan event, 8), done: make(chan struct{})}
	s := m.newSession(newFakeConn(), a, 1, false)
	if s == nil {
		t.Fatal("session construction failed")
	}
	if phase := s.protocolSnapshot().Phase(); phase != protocol.WaitCEA {
		t.Fatalf("published initiator phase=%v, want WaitCEA", phase)
	}
	if len(s.writes) != 0 {
		t.Fatal("CER published before dial completion")
	}
	s.close()
	m.wg.Wait()
	closeManager(t, m, nil)
}

type heldCoreFailureConn struct {
	*fakeConn
	entered, release chan struct{}
	err              error
}

func (c *heldCoreFailureConn) WriteStream(_ []byte, _ uint) (int, error) {
	close(c.entered)
	<-c.release
	return 0, c.err
}

func TestAttemptedRequiredReplyReportsFailureAfterRetirement(t *testing.T) {
	a, s, _ := newReportingRawActor(t)
	reportingOpen(t, s)
	want := errors.New("required reply transport failure")
	c := &heldCoreFailureConn{fakeConn: s.c.(*fakeConn), entered: make(chan struct{}), release: make(chan struct{}), err: want}
	s.c = c
	events := make(chan diam.ProtocolErrorEvent, 1)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	a.onWire(event{s: s, msg: watchdogRequest(t)})
	w := requiredQueuedWrite(t, s)
	done := make(chan struct{})
	go func() { s.writeProtocol(w); close(done) }()
	<-c.entered
	s.retired.Store(true)
	s.applyProtocol(protocol.Input{Kind: protocol.Retire}, nil)
	close(c.release)
	<-done
	select {
	case e := <-events:
		if e.Err.Kind() != diam.ProtocolReplyFailure || e.Reply != diam.ProtocolReplyFailed || e.ReplyCode != diam.Success {
			t.Fatalf("attempted reply failure=%+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement erased an attempted required reply's failure")
	}
}

func TestFailedCoreQueueDisposesWriterWithoutEventCapacity(t *testing.T) {
	a, s, _ := newReportingRawActor(t)
	reportingOpen(t, s)
	a.events = make(chan event, 1)
	a.events <- event{}
	for len(s.writes) < cap(s.writes) {
		s.writes <- writeRequest{}
	}
	done := make(chan struct{})
	defer func() { close(a.done); <-done }()
	go func() { a.onWire(event{s: s, msg: watchdogRequest(t)}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("queue rejection waited for ordinary event capacity to dispose its writer")
	}
	if len(s.protocolSnapshot().Controls()) != 0 {
		t.Fatal("failed queue retained a control writer")
	}
}
