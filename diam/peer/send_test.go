package peer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func outboundTestManager(t *testing.T) (*Manager, []*actor, []*session) {
	t.Helper()
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	actors := make([]*actor, 0, 2)
	sessions := make([]*session, 0, 2)
	for i, host := range []datatype.DiameterIdentity{"a.example.net", "b.example.net"} {
		a := &actor{m: m, cfg: PeerConfig{Host: host}, done: make(chan struct{}), events: make(chan event, 8), state: IOpen, watchdog: WatchdogOkay, meta: &smpeer.Metadata{OriginHost: host, OriginRealm: "example.net", Applications: []uint32{4}}}
		c := newFakeConn()
		s := &session{m: m, c: c, actor: a, gen: uint64(i + 1), writes: make(chan writeRequest, 8), closed: make(chan struct{})}
		a.active, a.i = s, s
		a.publish(nil)
		close(a.done)
		m.peers[identity(host)] = a
		actors, sessions = append(actors, a), append(sessions, s)
	}
	t.Cleanup(func() {
		for _, s := range sessions {
			s.close()
		}
		closeManager(t, m, nil)
	})
	return m, actors, sessions
}

func outboundRequest(host, realm string) *diam.Message {
	r := diam.NewRequest(272, 4, nil)
	if host != "" {
		_, _ = r.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(host))
	}
	if realm != "" {
		_, _ = r.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(realm))
	}
	return r
}

func TestOutboundSelection(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "EXAMPLE.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	selectHost := func(req *diam.Message, want string, wantErr error) {
		t.Helper()
		a, _, err := m.selectPeer(req, nil)
		if !errors.Is(err, wantErr) {
			t.Fatalf("select error = %v want %v", err, wantErr)
		}
		if wantErr == nil && string(a.cfg.Host) != want {
			t.Fatalf("selected %s want %s", a.cfg.Host, want)
		}
	}
	selectHost(outboundRequest("b.example.net", "example.net"), "b.example.net", nil)
	selectHost(outboundRequest("", "EXAMPLE.NET"), "a.example.net", nil)
	actors[0].watchdog = WatchdogSuspect
	actors[0].publish(nil)
	selectHost(outboundRequest("", "example.net"), "b.example.net", nil)
	selectHost(outboundRequest("a.example.net", "example.net"), "", ErrUnableToDeliver)
	selectHost(outboundRequest("a.example.net", "other.net"), "", ErrUnableToDeliver)
	actors[1].meta.Applications = []uint32{0xffffffff}
	actors[1].publish(nil)
	selectHost(outboundRequest("", "example.net"), "b.example.net", nil)
	actors[1].meta.Applications = []uint32{5}
	actors[1].publish(nil)
	selectHost(outboundRequest("", "example.net"), "", ErrUnableToDeliver)
	selectHost(outboundRequest("", "missing.net"), "", ErrNoRoute)
	selectHost(outboundRequest("", ""), "", ErrNoRoute)
	actors[1].meta.Applications = []uint32{4}
	actors[1].publish(nil)
	if err := m.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	selectHost(outboundRequest("b.example.net", "example.net"), "b.example.net", nil)
	selectHost(outboundRequest("", "example.net"), "", ErrNoRoute)
	_ = sessions
}

func TestConfiguredDestinationNeverFallsThroughToRoute(t *testing.T) {
	m, actors, _ := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	request := outboundRequest("a.example.net", "example.net")
	actors[0].meta.Applications = []uint32{5}
	actors[0].publish(nil)
	if a, _, err := m.selectPeer(request, nil); a != nil || !errors.Is(err, ErrUnableToDeliver) {
		t.Fatalf("unnegotiated final destination selected %v: %v", a, err)
	}
	actors[0].meta.Applications = []uint32{4}
	actors[0].publish(nil)
	if a, _, err := m.selectPeer(request, map[*actor]bool{actors[0]: true}); a != nil || !errors.Is(err, ErrUnableToDeliver) {
		t.Fatalf("failed final destination rerouted to %v: %v", a, err)
	}
}

func TestConfiguredDestinationInFlightNeverReroutes(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	result := sendAsync(m, context.Background(), outboundRequest("a.example.net", "example.net"))
	_ = nextWrite(t, sessions[0])
	actors[0].changeWatchdog(WatchdogSuspect, errors.New("silent"))
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrUnableToDeliver) && !errors.Is(got.err, ErrFailover) {
			t.Fatalf("fixed destination failover = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("fixed destination did not complete")
	}
	select {
	case w := <-sessions[1].writes:
		t.Fatalf("fixed destination rerouted to B: %+v", w.msg.Header)
	default:
	}
}

func TestSendCopiesMessageAndMatchesAnswer(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	req := outboundRequest("", "example.net")
	before, err := req.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		answer *diam.Message
		err    error
	}
	got := make(chan result, 1)
	go func() { answer, err := m.Send(context.Background(), req); got <- result{answer, err} }()
	var sent *diam.Message
	select {
	case w := <-sessions[0].writes:
		sent = w.msg
	case <-time.After(time.Second):
		t.Fatal("request not queued")
	}
	if sent.Header.EndToEndID == req.Header.EndToEndID {
		t.Fatal("End-to-End ID not assigned")
	}
	answer := sent.Answer(diam.Success)
	m.receiveAnswer(sessions[0], answer)
	select {
	case r := <-got:
		if r.err != nil || r.answer != answer {
			t.Fatalf("Send = %p, %v", r.answer, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send did not complete")
	}
	after, err := req.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Send mutated caller message")
	}
}

func sendAsync(m *Manager, ctx context.Context, req *diam.Message) <-chan sendResult {
	result := make(chan sendResult, 1)
	go func() { answer, err := m.Send(ctx, req); result <- sendResult{answer: answer, err: err} }()
	return result
}

func nextWrite(t *testing.T, s *session) *diam.Message {
	t.Helper()
	select {
	case w := <-s.writes:
		return w.msg
	case <-time.After(time.Second):
		t.Fatal("missing outbound write")
		return nil
	}
}

func TestAnswerMatchingRejectsWrongGenerationAndIdentifiers(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	request := nextWrite(t, sessions[0])
	wrongLeg := request.Answer(diam.Success)
	m.receiveAnswer(sessions[1], wrongLeg)
	oldGen := sessions[0].gen
	sessions[0].bind(sessions[0].actor, oldGen+1)
	m.receiveAnswer(sessions[0], request.Answer(diam.Success))
	sessions[0].bind(sessions[0].actor, oldGen)
	for _, mutate := range []func(*diam.Message){
		func(m *diam.Message) { m.Header.EndToEndID++ },
		func(m *diam.Message) { m.Header.CommandCode++ },
		func(m *diam.Message) { m.Header.ApplicationID++ },
		func(m *diam.Message) { m.Header.HopByHopID++ },
		func(m *diam.Message) { m.Header.CommandFlags |= diam.RetransmittedFlag },
	} {
		bad := request.Answer(diam.Success)
		mutate(bad)
		m.receiveAnswer(sessions[0], bad)
	}
	select {
	case r := <-result:
		t.Fatalf("mismatched answer completed request: %+v", r)
	default:
	}
	m.receiveAnswer(sessions[0], request.Answer(diam.Success))
	if r := <-result; r.err != nil || r.answer == nil {
		t.Fatalf("valid answer = %+v", r)
	}
	if len(m.pending) != 0 {
		t.Fatalf("pending after answer = %v", m.pending)
	}
}

func TestFailoverKeepsEndToEndAndSetsTOnlyOnRetry(t *testing.T) {
	for _, winner := range []int{0, 1} {
		t.Run(string(rune('A'+winner)), func(t *testing.T) {
			m, actors, sessions := outboundTestManager(t)
			if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
				t.Fatal(err)
			}
			result := sendAsync(m, context.Background(), outboundRequest("target.example.net", "example.net"))
			first := nextWrite(t, sessions[0])
			if first.Header.CommandFlags&diam.RetransmittedFlag != 0 {
				t.Fatal("first send has T bit")
			}
			actors[0].changeWatchdog(WatchdogSuspect, errors.New("silent"))
			second := nextWrite(t, sessions[1])
			if second.Header.CommandFlags&diam.RetransmittedFlag == 0 || second.Header.EndToEndID != first.Header.EndToEndID || second.Header.HopByHopID == first.Header.HopByHopID {
				t.Fatalf("failover IDs/flags first=%+v second=%+v", first.Header, second.Header)
			}
			originalHost, _ := destination(second, avp.DestinationHost)
			if originalHost != "target.example.net" {
				t.Fatalf("rewrote Destination-Host to %s", originalHost)
			}
			// Closing the old SUSPECT leg must not schedule another failover.
			if winner == 1 {
				sessions[0].close()
			}
			m.receiveAnswer(sessions[winner], []*diam.Message{first, second}[winner].Answer(diam.Success))
			if r := <-result; r.err != nil || r.answer == nil {
				t.Fatalf("winner result = %+v", r)
			}
			m.receiveAnswer(sessions[1-winner], []*diam.Message{first, second}[1-winner].Answer(diam.Success))
			if len(m.pending) != 0 {
				t.Fatalf("late loser retained pending: %v", m.pending)
			}
		})
	}
}

func TestRequestTimeoutCancelAndPendingLimit(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	clock := &fakeClock{}
	m.cfg.Clock = clock
	m.cfg.Limits.PendingPerPeer = 1
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	first := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	_ = nextWrite(t, sessions[0])
	if _, err := m.Send(context.Background(), outboundRequest("", "example.net")); !errors.Is(err, ErrPendingFull) {
		t.Fatalf("pending limit error = %v", err)
	}
	for {
		clock.mu.Lock()
		n := len(clock.timers)
		clock.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clock.fire()
	if r := <-first; !errors.Is(r.err, ErrRequestTimeout) {
		t.Fatalf("timeout result = %+v", r)
	}
	if len(m.pending) != 0 {
		t.Fatal("timeout retained pending")
	}
	ctx, cancel := context.WithCancel(context.Background())
	second := sendAsync(m, ctx, outboundRequest("", "example.net"))
	_ = nextWrite(t, sessions[0])
	cancel()
	if r := <-second; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("cancel result = %+v", r)
	}
	if len(m.pending) != 0 {
		t.Fatal("cancel retained pending")
	}
}

func TestCustomEndToEndGeneratorAndHopWrap(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	m.cfg.EndToEnd = func() uint32 { return 0x12345678 }
	atomic.StoreUint32(&m.nextHop, ^uint32(0)-1)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	first := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	f := nextWrite(t, sessions[0])
	atomic.StoreUint32(&m.nextHop, f.Header.HopByHopID-1) // force a reused candidate across wrap
	second := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	s := nextWrite(t, sessions[0])
	if f.Header.EndToEndID != 0x12345678 || s.Header.EndToEndID != 0x12345678 || f.Header.HopByHopID == s.Header.HopByHopID {
		t.Fatalf("IDs first=%+v second=%+v", f.Header, s.Header)
	}
	m.receiveAnswer(sessions[0], f.Answer(diam.Success))
	m.receiveAnswer(sessions[0], s.Answer(diam.Success))
	if r := <-first; r.err != nil {
		t.Fatal(r.err)
	}
	if r := <-second; r.err != nil {
		t.Fatal(r.err)
	}
}

func TestManagedHopSkipsOutstandingControlRequest(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	control := diam.NewRequest(diam.DeviceWatchdog, 0, nil)
	if !sessions[0].sendControl(control) {
		t.Fatal("control request not queued")
	}
	_ = nextWrite(t, sessions[0])
	atomic.StoreUint32(&m.nextHop, control.Header.HopByHopID-1)
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	business := nextWrite(t, sessions[0])
	if business.Header.HopByHopID == control.Header.HopByHopID {
		t.Fatal("managed Hop-by-Hop collided with outstanding DWR")
	}
	m.receiveAnswer(sessions[0], business.Answer(diam.Success))
	if r := <-result; r.err != nil {
		t.Fatal(r.err)
	}
}

func TestControlReservationReleasedIfSessionClosed(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	s := sessions[0]
	s.close()
	for range 64 {
		if s.sendControl(diam.NewRequest(diam.DeviceWatchdog, 0, nil)) {
			t.Fatal("closed session accepted control request")
		}
		if len(m.controls[s]) != 0 {
			t.Fatal("closed session retained control Hop-by-Hop")
		}
	}
}

func TestFirstSendClearsCallerTAndRejectsInvalid(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	request := outboundRequest("", "example.net")
	request.Header.CommandFlags |= diam.RetransmittedFlag
	result := sendAsync(m, context.Background(), request)
	sent := nextWrite(t, sessions[0])
	if sent.Header.CommandFlags&diam.RetransmittedFlag != 0 || request.Header.CommandFlags&diam.RetransmittedFlag == 0 {
		t.Fatal("first-send T handling changed caller or wire")
	}
	m.receiveAnswer(sessions[0], sent.Answer(diam.Success))
	<-result
	for _, bad := range []*diam.Message{nil, diam.NewRequest(diam.DeviceWatchdog, 0, nil), outboundRequest("", "example.net").Answer(0)} {
		if _, err := m.Send(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid %v: %v", bad, err)
		}
	}
}

func TestConnectionLossFailsOverAndNoAlternateFails(t *testing.T) {
	for _, route := range [][]datatype.DiameterIdentity{{"a.example.net", "b.example.net"}, {"a.example.net"}} {
		t.Run(string(rune('0'+len(route))), func(t *testing.T) {
			m, _, sessions := outboundTestManager(t)
			if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: route}}); err != nil {
				t.Fatal(err)
			}
			result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
			first := nextWrite(t, sessions[0])
			sessions[0].close()
			if len(route) == 1 {
				if r := <-result; !errors.Is(r.err, ErrFailover) {
					t.Fatalf("no alternate = %+v", r)
				}
				return
			}
			second := nextWrite(t, sessions[1])
			if first.Header.EndToEndID != second.Header.EndToEndID || second.Header.CommandFlags&diam.RetransmittedFlag == 0 {
				t.Fatal("connection-loss retry changed E2E or omitted T")
			}
			m.receiveAnswer(sessions[1], second.Answer(diam.Success))
			if r := <-result; r.err != nil {
				t.Fatal(r.err)
			}
		})
	}
}

func TestAdmissionFailureLeavesFailoverOwnerAndDeadline(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	clock := &fakeClock{}
	m.cfg.Clock = clock
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	// Close A after the pending reservation but before queue admission.
	sessions[0].beforeAdmission = sessions[0].close
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	retry := nextWrite(t, sessions[1])
	select {
	case premature := <-result:
		t.Fatalf("Send returned while B owns request: %+v", premature)
	default:
	}
	clock.mu.Lock()
	armed := len(clock.timers)
	clock.mu.Unlock()
	if armed == 0 {
		t.Fatal("failover request has no deadline")
	}
	m.receiveAnswer(sessions[1], retry.Answer(diam.Success))
	if got := <-result; got.err != nil || got.answer == nil {
		t.Fatalf("failover result = %+v", got)
	}
}

func TestFixedDestinationDoesNotRerouteDuringClosePublication(t *testing.T) {
	m, _, sessions := outboundTestManager(t)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	sessions[0].close() // close can precede the actor's next published snapshot
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.Send(ctx, outboundRequest("a.example.net", "example.net")); !errors.Is(err, ErrUnableToDeliver) {
		t.Fatalf("fixed down destination = %v", err)
	}
	select {
	case w := <-sessions[1].writes:
		t.Fatalf("rerouted fixed request to B: %+v", w.msg.Header)
	default:
	}
}

type failingWriteConn struct{ *fakeConn }

func (c *failingWriteConn) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func (c *failingWriteConn) WriteStream([]byte, uint) (int, error) {
	return 0, errors.New("write failed")
}

func TestWriteErrorRetiresConnectionAndFailsOver(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	bad := m.newSession(&failingWriteConn{newFakeConn()}, actors[0], 8, false)
	actors[0].active, actors[0].i = bad, bad
	actors[0].publish(nil)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	second := nextWrite(t, sessions[1])
	if second.Header.CommandFlags&diam.RetransmittedFlag == 0 {
		t.Fatal("write error did not set T on alternate")
	}
	select {
	case <-bad.closed:
	default:
		t.Fatal("write-error connection remained open")
	}
	m.receiveAnswer(sessions[1], second.Answer(diam.Success))
	if r := <-result; r.err != nil {
		t.Fatal(r.err)
	}
}

func TestFailoverWriteErrorContinuesToThirdPeer(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	bad := m.newSession(&failingWriteConn{newFakeConn()}, actors[1], 8, false)
	actors[1].active, actors[1].i = bad, bad
	actors[1].publish(nil)
	cActor := &actor{m: m, cfg: PeerConfig{Host: "c.example.net"}, done: make(chan struct{}), events: make(chan event, 8), state: IOpen, watchdog: WatchdogOkay, meta: &smpeer.Metadata{OriginHost: "c.example.net", OriginRealm: "example.net", Applications: []uint32{4}}}
	cSession := &session{m: m, c: newFakeConn(), actor: cActor, gen: 9, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	cActor.active, cActor.i = cSession, cSession
	cActor.publish(nil)
	close(cActor.done)
	m.peers["c.example.net"] = cActor
	t.Cleanup(cSession.close)
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net", "c.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	_ = nextWrite(t, sessions[0])
	actors[0].changeWatchdog(WatchdogSuspect, errors.New("silent"))
	third := nextWrite(t, cSession)
	if third.Header.CommandFlags&diam.RetransmittedFlag == 0 {
		t.Fatal("third attempt missing T")
	}
	m.receiveAnswer(cSession, third.Answer(diam.Success))
	if r := <-result; r.err != nil {
		t.Fatal(r.err)
	}
}

func TestFailoverRetainsOriginalRequestDeadline(t *testing.T) {
	m, actors, sessions := outboundTestManager(t)
	clock := &fakeClock{}
	m.cfg.Clock = clock
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	_ = nextWrite(t, sessions[0])
	actors[0].changeWatchdog(WatchdogSuspect, errors.New("silent"))
	_ = nextWrite(t, sessions[1])
	clock.mu.Lock()
	count := len(clock.timers)
	clock.mu.Unlock()
	if count != 1 {
		t.Fatalf("failover installed %d request timers", count)
	}
	clock.fire()
	if r := <-result; !errors.Is(r.err, ErrRequestTimeout) {
		t.Fatalf("deadline result = %+v", r)
	}
}

func TestOneCompletionAcrossAnswersTimeoutAndCancel(t *testing.T) {
	for _, winner := range []string{"original", "alternate", "timeout", "cancel", "concurrent"} {
		t.Run(winner, func(t *testing.T) {
			m, actors, sessions := outboundTestManager(t)
			clock := &fakeClock{}
			m.cfg.Clock = clock
			if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net", "b.example.net"}}}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := sendAsync(m, ctx, outboundRequest("", "example.net"))
			original := nextWrite(t, sessions[0])
			actors[0].changeWatchdog(WatchdogSuspect, errors.New("silent"))
			alternate := nextWrite(t, sessions[1])
			for {
				clock.mu.Lock()
				n := len(clock.timers)
				clock.mu.Unlock()
				if n > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			actions := map[string]func(){
				"original":  func() { m.receiveAnswer(sessions[0], original.Answer(diam.Success)) },
				"alternate": func() { m.receiveAnswer(sessions[1], alternate.Answer(diam.Success)) },
				"timeout":   clock.fire,
				"cancel":    cancel,
			}
			if winner == "concurrent" {
				var wg sync.WaitGroup
				for _, action := range actions {
					wg.Add(1)
					go func(action func()) { defer wg.Done(); action() }(action)
				}
				wg.Wait()
			} else {
				actions[winner]()
			}
			var first sendResult
			select {
			case first = <-result:
			case <-time.After(time.Second):
				t.Fatal("no completion")
			}
			if winner == "original" || winner == "alternate" {
				if first.err != nil || first.answer == nil {
					t.Fatalf("answer winner = %+v", first)
				}
			}
			if winner == "timeout" && !errors.Is(first.err, ErrRequestTimeout) {
				t.Fatalf("timeout winner = %+v", first)
			}
			if winner == "cancel" && !errors.Is(first.err, context.Canceled) {
				t.Fatalf("cancel winner = %+v", first)
			}
			for _, action := range actions {
				action()
			}
			if len(m.pending) != 0 {
				t.Fatalf("completion retained pending: %v", m.pending)
			}
			select {
			case extra := <-result:
				t.Fatalf("duplicate completion %+v", extra)
			default:
			}
		})
	}
}
