package sm

import (
	"bytes"
	"runtime"
	"sync"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// RFC 6733 §5.4: committed application work is likely in flight even before
// the dispatch executor starts it. A custom Conn need not expose a tracker.
func TestAcceptedHandlersCommittedBeforeRun(t *testing.T) {
	for _, mode := range []string{"handshake", "following", "external"} {
		t.Run(mode, func(t *testing.T) {
			external := mode == "external"
			c := newHandshakeConn()
			cfg := testMessageErrorSettings(c.Dictionary())
			cfg.ValidateRequests = false
			cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
			sm := mustNewStateMachine(t, cfg, c.Dictionary())
			sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) {}))
			var state *acceptedHandshake
			if external {
				replaceAdmission(c, "CER")
				state = sm.acceptedCore(c, diam.NewRequest(999, 1001, c.Dictionary()), true)
			} else {
				state = primeAcceptedTestCore(t, sm, c)
				if mode != "following" {
					state.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: state.snapshot().Admission()})
				}
			}
			defer state.apply(protocol.Input{Kind: protocol.Abort})
			request := diam.NewRequest(999, 1001, c.Dictionary())
			batch := state.prepare(protocol.Input{Kind: protocol.Receive, Message: request})
			if mode == "following" {
				batch = state.prepare(protocol.Input{Kind: protocol.ReleaseAdmission, Token: state.snapshot().Admission()})
				if len(batch.following) != 1 {
					t.Fatalf("following batches=%d; want=1", len(batch.following))
				}
			}
			admitted := batch
			if mode == "following" {
				admitted = batch.following[0]
			}
			found := false
			for _, e := range admitted.effects {
				found = found || e.Kind == protocol.Admit
			}
			if !found {
				t.Fatalf("application was not admitted: %+v", batch.effects)
			}
			dpr := acceptedDPR(t)
			if external {
				for _, a := range dpr.AVP {
					if a.Code == avp.OriginHost {
						a.Data = datatype.DiameterIdentity("saved.example")
					}
				}
			}
			state.apply(protocol.Input{Kind: protocol.Receive, Message: dpr})
			raw := protocolGenerationAwait(t, c.writes)
			answer, err := diam.ReadMessage(bytes.NewReader(raw), c.Dictionary())
			if err != nil || !testResultCode(answer, diam.UnableToComply) || answer.Header.HopByHopID != dpr.Header.HopByHopID || answer.Header.EndToEndID != dpr.Header.EndToEndID {
				t.Fatalf("committed handler DPA=%v err=%v", answer, err)
			}
			state.run(batch)
			state.apply(protocol.Input{Kind: protocol.Receive, Message: dpr})
			raw = protocolGenerationAwait(t, c.writes)
			answer, err = diam.ReadMessage(bytes.NewReader(raw), c.Dictionary())
			if err != nil || !testResultCode(answer, diam.Success) {
				t.Fatalf("returned handler DPA=%v err=%v", answer, err)
			}
		})
	}
}

// External admission keeps its own claims and the same §5.4 handler accounting.
func TestAdmittedRequestHandlerDPRWire(t *testing.T) {
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	p := newProtocolDeliveryWire(t, 8, false, func(cfg *Settings) {
		cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
	}, func(server *diam.Server) {
		opened := server.OnNewConnection
		server.OnNewConnection = func(c diam.Conn) { replaceAdmission(c, "CER"); opened(c) }
		sm := server.Handler.(*StateMachine)
		server.Handler = diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
			sm.ServeDIAM(c, m)
			if m.Header.CommandCode == 0xeeff {
				close(returned)
			}
		})
	})
	t.Cleanup(unblock)
	p.sm.Handle("ALL", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		close(started)
		<-release
		if _, err := m.Answer(diam.Success).WriteTo(c); err != nil {
			t.Error(err)
		}
	}))
	request := diam.NewMessage(0xeeff, diam.RequestFlag, 1001, 91, 92, p.conn.Dictionary())
	p.send(t, request)
	protocolGenerationAwait(t, started)
	dpr := acceptedDPR(t)
	for _, a := range dpr.AVP {
		if a.Code == avp.OriginHost {
			a.Data = datatype.DiameterIdentity("saved.example")
		}
	}
	header := p.send(t, dpr)
	answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
	if err != nil || !testResultCode(answer, diam.UnableToComply) || answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID {
		t.Fatalf("external DPA=%v err=%v", answer, err)
	}
	unblock()
	answer, err = diam.ReadMessage(p.peer, p.conn.Dictionary())
	if err != nil || !testResultCode(answer, diam.Success) || answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
		t.Fatalf("external handler answer=%v err=%v", answer, err)
	}
	protocolGenerationAwait(t, returned)
	p.send(t, dpr)
	answer, err = diam.ReadMessage(p.peer, p.conn.Dictionary())
	if err != nil || !testResultCode(answer, diam.Success) {
		t.Fatalf("drained external DPA=%v err=%v", answer, err)
	}
	select {
	case e := <-p.events:
		t.Fatalf("unexpected event=%+v", e)
	default:
	}
}

func acceptedHandlerBatchFixture(t *testing.T, ready bool) (*StateMachine, *handshakeConn, *acceptedHandshake) {
	t.Helper()
	c := newHandshakeConn()
	cfg := testMessageErrorSettings(c.Dictionary())
	cfg.ValidateRequests = false
	cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
	sm := mustNewStateMachine(t, cfg, c.Dictionary())
	state := primeAcceptedTestCore(t, sm, c)
	if ready {
		state.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: state.snapshot().Admission()})
	}
	t.Cleanup(func() { state.apply(protocol.Input{Kind: protocol.Abort}) })
	return sm, c, state
}

func acceptedHandlerBatchDPA(t *testing.T, c *handshakeConn, state *acceptedHandshake) {
	t.Helper()
	dpr := acceptedDPR(t)
	state.apply(protocol.Input{Kind: protocol.Receive, Message: dpr})
	answer, err := diam.ReadMessage(bytes.NewReader(protocolGenerationAwait(t, c.writes)), c.Dictionary())
	if err != nil || answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.CommandFlags != 0 || answer.Header.HopByHopID != dpr.Header.HopByHopID || answer.Header.EndToEndID != dpr.Header.EndToEndID || !testResultCode(answer, diam.Success) {
		t.Fatalf("abandoned batch DPA=%v err=%v; want correlated 2001", answer, err)
	}
	if n := state.runningHandlers.Load(); n != 0 {
		t.Fatalf("running handlers=%d after batch unwinding; want=0", n)
	}
}

// RFC 6733 §5.4: replay that is abandoned by a preceding panic is no longer
// work in flight, even when the connection survives an outer recovery.
func TestAcceptedHandlersAbandonedFollowing(t *testing.T) {
	sm, c, state := acceptedHandlerBatchFixture(t, false)
	calls := 0
	sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls++; panic("synthetic replay panic") }))
	for range 2 {
		held := state.prepare(protocol.Input{Kind: protocol.Receive, Message: diam.NewRequest(999, 1001, c.Dictionary())})
		state.run(held)
	}
	batch := state.prepare(protocol.Input{Kind: protocol.ReleaseAdmission, Token: state.snapshot().Admission()})
	if len(batch.following) != 2 {
		t.Fatalf("following batches=%d; want=2", len(batch.following))
	}
	var recovered any
	func() { defer func() { recovered = recover() }(); state.run(batch) }()
	if recovered != "synthetic replay panic" || calls != 1 {
		t.Fatalf("recovered=%v handler calls=%d; want synthetic replay panic and one call", recovered, calls)
	}
	acceptedHandlerBatchDPA(t, c, state)
}

// RFC 6733 §5.4: a callback ending the batch before Admit owes no handler
// answer. Both panic and Goexit must release the committed reservation.
func TestAcceptedHandlersAbandonedBeforeAdmit(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			sm, c, state := acceptedHandlerBatchFixture(t, true)
			calls := 0
			sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { calls++ }))
			sm.cfg.OnDWR = func(diam.Conn, *diam.Message) {
				if mode == "goexit" {
					runtime.Goexit()
				}
				panic("synthetic pre-admit panic")
			}
			batch := state.prepare(protocol.Input{Kind: protocol.Receive, Message: diam.NewRequest(999, 1001, c.Dictionary())})
			batch.effects = append([]protocol.Effect{{Kind: protocol.RunHook, Message: regressionDWR(t)}}, batch.effects...)
			done := make(chan any, 1)
			go func() {
				var recovered any
				defer func() { done <- recovered }()
				defer func() { recovered = recover() }()
				state.run(batch)
			}()
			recovered := protocolGenerationAwait(t, done)
			if mode == "panic" && recovered != "synthetic pre-admit panic" || mode == "goexit" && recovered != nil {
				t.Fatalf("mode=%s recovered=%v", mode, recovered)
			}
			if calls != 0 {
				t.Fatalf("abandoned Admit called handler %d times", calls)
			}
			acceptedHandlerBatchDPA(t, c, state)
		})
	}
}
