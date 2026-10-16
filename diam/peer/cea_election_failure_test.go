package peer

import (
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestManagerInvalidCEAHeaderClosesElectionLegs(t *testing.T) {
	a, s, _ := failureReportingActor(t)
	a.m.cfg.Settings.OriginHost = "aaa.example.net"
	cer := reportingInitiator(t, a, s, true)
	r := &session{m: a.m, c: newFakeConn(), actor: a, inbound: true, gen: 2, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	t.Cleanup(r.close)
	if err := r.initProtocol(); err != nil {
		t.Fatal(err)
	}
	r.runProtocol(protocol.Input{Kind: protocol.Start}, r.takeStartup(), nil)
	// Hold responder admission while an initiator CER is outstanding.
	a.state = WaitICEA
	request, err := base.BuildCER(a.m.dictionary(), testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	r.applyProtocol(protocol.Input{Kind: protocol.Receive, Message: request}, nil)
	if a.state != WaitReturns || a.r != r || r.protocolSnapshot().Candidate() == 0 {
		t.Fatalf("candidate state=%s r=%v candidate=%d", a.state, a.r == r, r.protocolSnapshot().Candidate())
	}
	cea, err := base.BuildCEA(cer, testBase("known.example.net"), diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	cea.Header.CommandFlags |= diam.ProxiableFlag
	a.onWire(event{s: s, msg: cea})
	var retained bool
	for len(a.m.callbackQ) != 0 {
		e := <-a.m.callbackQ
		var cause *diam.MessageError
		if errors.As(e.Reason, &cause) && cause.ResultCode == diam.InvalidHDRBits {
			retained = true
		}
	}
	if !retained {
		t.Error("CEA failure notification lost its typed header error")
	}
	a.handle(event{kind: connGone, s: s})
	if a.state != Closed || !r.c.Closed() {
		t.Fatalf("invalid correlated CEA left state=%s responderClosed=%v responderWrites=%d", a.state, r.c.Closed(), len(r.writes))
	}
}

// A local close commits core termination before physical transport closure.
// Election can select that responder before the queued transport-loss event;
// the invalidated candidate keeps the core's silent stale-input disposition.
func TestManagerElectionIgnoresInvalidatedCERCandidate(t *testing.T) {
	a, s, records := failureReportingActor(t)
	reportingCandidate(t, a, s)
	if a.state != WaitConnAckElect || s.protocolSnapshot().Candidate() == 0 {
		t.Fatal("fixture did not hold a validated responder candidate")
	}
	for len(a.m.callbackQ) != 0 {
		<-a.m.callbackQ
	}
	s.abortProtocol()
	if s.protocolSnapshot().Phase() != protocol.Closed || s.c.Closed() {
		t.Fatal("fixture did not stop between core termination and transport closure")
	}
	a.pendingGen, a.dialing = 1, true
	err := errors.New("outbound dial failed")
	a.onDial(event{gen: 1, err: err})
	if a.state != ROpen || a.active != s || s.c.Closed() || len(s.writes) != 0 {
		t.Fatalf("invalidated candidate changed election disposition: state=%s active=%v closed=%v writes=%d", a.state, a.active == s, s.c.Closed(), len(s.writes))
	}
	if got := records.Records(); len(got) != 1 || got[0].Message != "peer: dial failed" {
		t.Fatalf("invalidated candidate emitted additional failure: %v", got)
	}
	assertFailureEvents(t, a, []PeerState{ROpen, ROpen}, []WatchdogState{WatchdogInitial, WatchdogInitial}, []string{"", err.Error()})
}
