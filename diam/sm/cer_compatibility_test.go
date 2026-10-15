package sm

import (
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// Malformed Client input enters HandleMessageError rather than decoded dispatch.
// Only decoded repeated CERs have historically crossed the OnCER hook boundary.
func TestClientRepeatedCERHookCompatibilityWire(t *testing.T) {
	var calls atomic.Int32
	p := newProtocolClientWire(t, func(c *Client) {
		c.Handler.cfg.OnCER = func(diam.Conn, *diam.Message) { calls.Add(1) }
	})
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil || result.conn != p.conn {
		t.Fatalf("Dial = %+v", result)
	}
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	malformed := regressionCER(t, testDict, 4)
	malformed.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown([]byte{1, 2})))
	header := p.send(t, malformed)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	if got := calls.Load(); got != 0 {
		t.Errorf("malformed repeated CER invoked OnCER %d times, want 0", got)
	}
	logs := p.logs.Records()
	if len(logs) != 2 || logs[0].Message != "diam: malformed message" || logs[0].Level != slog.LevelWarn || logs[1].Message != "sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible" || logs[1].Level != slog.LevelWarn {
		t.Fatalf("malformed repeated CER logs = %v", logs)
	}
	header = p.send(t, regressionCER(t, testDict, 4))
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	if got := calls.Load(); got != 1 {
		t.Errorf("decoded repeated CER hook total = %d, want 1", got)
	}
	if p.conn.Closed() {
		t.Fatal("repeated CER closed admitted Client")
	}
	p.noExtraEvents(t)
}

func TestAcceptedSemanticCERRejectionLogCompatibilityWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		app      uint32
		security bool
		code     uint32
		cause    error
	}{
		{"no_common_application", 0x00fffffe, false, diam.NoCommonApplication, smparser.ErrNoCommonApplication},
		{"no_common_security", 1001, true, diam.NoCommonSecurity, smparser.ErrNoCommonSecurity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProtocolWire(t, nil, false)
			testDict := newSMTestDictionary(creditcontrol.Dictionary())
			cer := regressionCER(t, testDict, tc.app)
			if tc.security {
				cer.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(1)))
			}
			header := p.send(t, cer)
			answer, err := diam.ReadMessage(p.peer, testDict)
			if err != nil || !testResultCode(answer, tc.code) {
				t.Fatalf("rejected CEA = %v, error = %v, want result %d", answer, err, tc.code)
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolCERRejected, tc.code, true, diam.ProtocolReplyWritten, tc.code)
			p.closed(t)
			logs := p.logs.Records()
			if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "sm: rejected CER; closing connection" {
				t.Fatalf("CER rejection logs = %v", logs)
			}
			cause := logtest.Attr(logs[0], "error").Any()
			if cause != tc.cause {
				t.Fatalf("CER rejection log cause = %v (%T), want original sentinel %v (%T)", cause, cause, tc.cause, tc.cause)
			}
		})
	}
}
