package peer

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type orderedReplyConn struct {
	*fakeConn
	release <-chan struct{}
	wrote   chan struct{}
	closes  atomic.Int32
	success bool
}

func (c *orderedReplyConn) Close() {
	c.closes.Add(1)
	c.fakeConn.Close()
}

func (c *orderedReplyConn) WriteStream(b []byte, _ uint) (int, error) {
	if c.release != nil {
		<-c.release
	}
	close(c.wrote)
	if c.success {
		return len(b), nil
	}
	return 0, io.ErrClosedPipe
}

func orderedReplyRejection(t *testing.T, m *Manager, s *session, command string, d *protocolDelivery) *diam.Message {
	t.Helper()
	msg := diam.NewMessage(0xeeee, diam.RequestFlag, 0, 11, 12, m.dictionary())
	switch command {
	case "unsupported":
		reportingReceive(s.actor, s, msg, d)
	case "rejection":
		msg = watchdogRequest(t)
		msg.AVP = nil
		reportingReceive(s.actor, s, msg, d)
	case "malformed":
		msg = watchdogRequest(t)
		s.actor.commit(event{kind: wireEvent, s: s, msg: msg, messageErr: &diam.MessageError{ResultCode: diam.InvalidAVPLength}}, d)
	case "malformed_pre_CER":
		s.inbound = true
		msg = capabilitiesExchangeRequest(t)
		s.actor.commit(event{kind: wireEvent, s: s, msg: msg, messageErr: &diam.MessageError{ResultCode: diam.InvalidAVPLength}}, d)
	case "rejected_CEA":
		msg = s.cerRequest
		s.actor.commit(event{testHook: func() { reportingRejectCandidate(s, msg, diam.NoCommonApplication, d) }}, d)
	default:
		t.Fatal("unknown rejection")
	}
	return msg
}

func orderedReplyWriter(t *testing.T, s *session) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	s.m.wg.Add(1)
	go func() { defer close(done); s.writer() }()
	t.Cleanup(func() {
		s.close()
		orderedReplyWait(t, done, "writer exit")
	})
	return done
}

func orderedReplyWait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestRequiredReplyConcurrentCompletionWaitsForAdmission(t *testing.T) {
	for _, command := range []string{"unsupported", "rejection", "malformed", "malformed_pre_CER", "rejected_CEA"} {
		t.Run(command, func(t *testing.T) {
			a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
			if command == "malformed_pre_CER" || command == "rejected_CEA" {
				a, s, _ = newReportingRawActor(t)
				if command == "rejected_CEA" {
					reportingCandidate(t, a, s)
				} else {
					reportingResponder(t, a, s)
					a.r = s
				}
			}
			reportingStartActor(t, a)
			c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), wrote: make(chan struct{})}
			s.c = c
			events := make(chan diam.ProtocolErrorEvent, 4)
			a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			done := orderedReplyWriter(t, s)
			d := newProtocolDelivery()
			msg := orderedReplyRejection(t, a.m, s, command, d)
			original := *msg.Header
			orderedReplyWait(t, done, "failed writer without admission observer")
			reportingAwaitReplyFailure(t, d)
			select {
			case e := <-events:
				t.Fatalf("completion overtook queued admission: reply=%v closing=%t", e.Reply, e.Closing)
			default:
			}
			msg.Header.HopByHopID++
			msg.AVP = nil
			d.deliver(a.m)
			for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
				select {
				case e := <-events:
					if e.Reply != want || !e.Message.HasHeader || e.Message.Header != original || e.ReplyCode == 0 {
						t.Fatalf("notification %d lost order or request metadata: %+v", i, e)
					}
					if i == 1 && (!e.Closing || !errors.Is(e.Err, diam.ProtocolReplyFailure)) {
						t.Fatalf("completion was not a typed closing failure: %+v", e)
					}
				default:
					t.Fatalf("missing notification %d (%v)", i, want)
				}
			}
			if len(events) != 0 || c.closes.Load() != 1 {
				t.Fatalf("duplicate completion or close: events=%d closes=%d", len(events), c.closes.Load())
			}
		})
	}
}

func TestRequiredReplyConcurrentCompletionWaitsForBlockedObserver(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	releaseWrite := make(chan struct{})
	c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), release: releaseWrite, wrote: make(chan struct{})}
	s.c = c
	queued := make(chan struct{})
	releaseObserver := make(chan struct{})
	events := make(chan diam.ProtocolErrorEvent, 4)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		if e.Reply == diam.ProtocolReplyQueued {
			// An observer may close its transport after admission is released.
			e.Conn.Close()
			close(queued)
			<-releaseObserver
		}
		events <- e
	}
	done := orderedReplyWriter(t, s)
	d := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s, "unsupported", d)
	delivered := make(chan struct{})
	go func() { defer close(delivered); d.deliver(a.m) }()
	orderedReplyWait(t, queued, "queued observer")
	close(releaseWrite)
	orderedReplyWait(t, done, "failed writer while observer blocked")
	reportingAwaitReplyFailure(t, d)
	select {
	case e := <-events:
		close(releaseObserver)
		orderedReplyWait(t, delivered, "admission observer")
		t.Fatalf("completion overtook blocked queued observer: reply=%v", e.Reply)
	default:
	}
	close(releaseObserver)
	orderedReplyWait(t, delivered, "admission observer")
	for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
		if e := orderedReplyEvent(t, events); e.Reply != want {
			t.Fatalf("notification %d=%v, want %v", i, e.Reply, want)
		}
	}
}

func orderedReplyEvent(t *testing.T, events <-chan diam.ProtocolErrorEvent) diam.ProtocolErrorEvent {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reply notification")
		return diam.ProtocolErrorEvent{}
	}
}

func TestRequiredReplyConcurrentCompletionAfterAdmission(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	release := make(chan struct{})
	c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), release: release, wrote: make(chan struct{})}
	s.c = c
	events := make(chan diam.ProtocolErrorEvent, 4)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	done := orderedReplyWriter(t, s)
	d := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s, "unsupported", d)
	d.deliver(a.m)
	if e := orderedReplyEvent(t, events); e.Reply != diam.ProtocolReplyQueued || e.Closing {
		t.Fatalf("untruthful admission: %+v", e)
	}
	close(release)
	orderedReplyWait(t, done, "writer after admission")
	if e := orderedReplyEvent(t, events); e.Reply != diam.ProtocolReplyFailed || !e.Closing {
		t.Fatalf("missing late failure: %+v", e)
	}
	if len(events) != 0 {
		t.Fatal("duplicate completion")
	}
}

func TestRequiredReplyConcurrentSuccessDoesNotReportFailure(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), wrote: make(chan struct{}), success: true}
	s.c = c
	events := make(chan diam.ProtocolErrorEvent, 4)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	done := orderedReplyWriter(t, s)
	d := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s, "unsupported", d)
	orderedReplyWait(t, c.wrote, "successful reply write")
	d.deliver(a.m)
	if e := orderedReplyEvent(t, events); e.Reply != diam.ProtocolReplyQueued || e.Closing {
		t.Fatalf("queued reply incorrectly reported as written or failed: %+v", e)
	}
	s.close()
	orderedReplyWait(t, done, "successful writer exit")
	if len(events) != 0 {
		t.Fatal("successful reply reported failure")
	}
}

func TestRequiredReplyConcurrentCompletionWithoutDeferredDelivery(t *testing.T) {
	for range 32 {
		a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
		reportingStartActor(t, a)
		c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), wrote: make(chan struct{})}
		s.c = c
		events := make(chan diam.ProtocolErrorEvent, 4)
		a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
		done := orderedReplyWriter(t, s)
		orderedReplyRejection(t, a.m, s, "unsupported", nil)
		orderedReplyWait(t, done, "writer without deferred admission")
		for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
			if e := orderedReplyEvent(t, events); e.Reply != want {
				t.Fatalf("notification %d=%v, want %v", i, e.Reply, want)
			}
		}
	}
}

func TestRequiredReplyConcurrentCompletionWithoutObserver(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	c := &orderedReplyConn{fakeConn: s.c.(*fakeConn), wrote: make(chan struct{})}
	s.c = c
	done := orderedReplyWriter(t, s)
	orderedReplyRejection(t, a.m, s, "unsupported", nil)
	orderedReplyWait(t, done, "writer with nil observer")
	if !c.Closed() || c.closes.Load() != 1 {
		t.Fatalf("nil observer changed failure close: closed=%t closes=%d", c.Closed(), c.closes.Load())
	}
}

func TestRequiredReplyConcurrentLeaseCompletionWaitsForAdmission(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	ready, release := make(chan struct{}), make(chan struct{})
	s.beforePublication = func(*diam.Message) { close(ready); <-release }
	events := make(chan diam.ProtocolErrorEvent, 4)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	done := orderedReplyWriter(t, s)
	d := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s, "unsupported", d)
	orderedReplyWait(t, ready, "publication gate")
	a.discovery.Store(&discoveryState{revoked: true})
	close(release)
	orderedReplyWait(t, done, "lease rejected writer")
	reportingAwaitReplyFailure(t, d)
	select {
	case e := <-events:
		t.Fatalf("lease completion overtook admission: reply=%v", e.Reply)
	default:
	}
	d.deliver(a.m)
	for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
		if e := orderedReplyEvent(t, events); e.Reply != want {
			t.Fatalf("lease notification %d=%v, want %v", i, e.Reply, want)
		}
	}
}

func TestRequiredReplyBlockedObserverDoesNotDelayAnotherReply(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	reportingStartActor(t, a)
	first := &orderedReplyConn{fakeConn: s.c.(*fakeConn), wrote: make(chan struct{})}
	s.c = first
	a2, s2, _ := newWatchdogTestActor(t, WatchdogOkay)
	second := &orderedReplyConn{fakeConn: s2.c.(*fakeConn), wrote: make(chan struct{})}
	s2.c = second
	// Independent actors share the protocol observer without sharing a mutation lock.
	a2.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { a.m.HandleProtocolError(e) }
	reportingStartActor(t, a2)
	queued, release := make(chan struct{}), make(chan struct{})
	events := make(chan diam.ProtocolErrorEvent, 8)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		if e.Conn == first && e.Reply == diam.ProtocolReplyQueued {
			close(queued)
			<-release
		}
		events <- e
	}
	done := orderedReplyWriter(t, s)
	d1 := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s, "unsupported", d1)
	orderedReplyWait(t, done, "first reply writer")
	delivered := make(chan struct{})
	go func() { defer close(delivered); d1.deliver(a.m) }()
	orderedReplyWait(t, queued, "first queued observer")
	defer func() { close(release); orderedReplyWait(t, delivered, "first observer exit") }()
	done2 := orderedReplyWriter(t, s2)
	d2 := newProtocolDelivery()
	orderedReplyRejection(t, a.m, s2, "unsupported", d2)
	orderedReplyWait(t, done2, "second reply writer")
	delivered2 := make(chan struct{})
	go func() { defer close(delivered2); d2.deliver(a.m) }()
	orderedReplyWait(t, delivered2, "independent second admission and completion")
	for i, want := range []diam.ProtocolReplyStatus{diam.ProtocolReplyQueued, diam.ProtocolReplyFailed} {
		if e := orderedReplyEvent(t, events); e.Conn != second || e.Reply != want {
			t.Fatalf("second reply notification %d did not pass blocked first observer: %+v", i, e)
		}
	}
}
