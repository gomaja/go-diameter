package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestMessageErrorHeaderDiagnosisPreservesFatalReport(t *testing.T) {
	c := newHandshakeConn()
	defer c.Close()
	c.SetContext(smpeer.NewContext(c.Context(), &smpeer.Metadata{OriginHost: "saved.example", OriginRealm: "example", CEA: &smparser.CEA{}}))
	cfg := testMessageErrorSettings(c.Dictionary())
	var events []diam.ProtocolErrorEvent
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
	sm := mustNewStateMachine(t, cfg, c.Dictionary())
	m := regressionDWR(t)
	m.Header.CommandFlags = diam.RetransmittedFlag
	if err := sm.HandleMessageError(c, m, &diam.MessageError{ResultCode: diam.MissingAVP, Fatal: true}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%v, want one error report", events)
	}
	e := events[0]
	if e.Err.Kind() != diam.ProtocolInvalidHeader || e.Err.ResultCode() != diam.InvalidHDRBits || !e.Closing || e.Reply != diam.ProtocolReplyNone || c.Closed() || len(c.writes) != 0 {
		t.Fatalf("kind=%s code=%d closing=%t reply=%v transportClosed=%t writes=%d, want invalid_header/3008/true/none/false/0", e.Err.Kind(), e.Err.ResultCode(), e.Closing, e.Reply, c.Closed(), len(c.writes))
	}
}
