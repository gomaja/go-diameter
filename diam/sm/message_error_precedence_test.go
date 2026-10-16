package sm

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func observeMessageErrorPrecedence(t *testing.T, admission, scenario, description string) string {
	t.Helper()
	logs := logtest.New()
	c := &messageErrorContractConn{handshakeConn: newHandshakeConn(), logger: logs.Logger()}
	c.dictionary = newSMTestDictionary(creditcontrol.Dictionary())
	cfg := testMessageErrorSettings(c.Dictionary())
	cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	local := []uint32{4}
	command, app := uint32(diam.ReAuth), uint32(4)
	unknown := false
	switch scenario {
	case "supported":
		cfg.ValidateRequests = true
	case "unsupported":
		cfg.ValidateRequests = true
		app = 9999
	case "unknown-command":
		command = 9999
	case "unsupported-command":
		cfg.ValidateRequests = true
		command = 9999
		app = 9999
	case "mandatory":
		cfg.RejectUnknownMandatoryAVPs = true
		unknown = true
	case "unsupported-mandatory":
		cfg.ValidateRequests = true
		cfg.RejectUnknownMandatoryAVPs = true
		app = 9999
		unknown = true
	case "relay-mandatory":
		cfg.ValidateRequests = true
		cfg.RejectUnknownMandatoryAVPs = true
		unknown = true
		local = []uint32{0xffffffff}
		cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(0xffffffff))}
	}
	var events []string
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
		events = append(events, fmt.Sprintf("%s/%d/%t/%d", e.Err.Kind(), e.Err.ResultCode(), e.Closing, e.Reply))
	}
	sm := mustNewStateMachine(t, cfg, c.Dictionary())
	if admission == "manual" {
		c.SetContext(smpeer.NewContext(context.WithValue(c.Context(), advertisedAppsKey{}, local), admissionMetadata("CEA")))
	} else {
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		remote := uint32(4)
		if scenario == "relay-mandatory" {
			remote = 0xffffffff
		}
		sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), remote))
		<-c.writes
	}
	events = nil
	beforeLogs := len(logs.Records())
	m := diam.NewMessage(command, diam.RequestFlag|diam.ProxiableFlag, app, 17, 18, c.Dictionary())
	if unknown {
		m.AddAVP(diam.NewAVP(0xfedc, avp.Mbit, 0, datatype.OctetString("unknown")))
		wire, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := diam.ReadMessage(bytes.NewReader(wire), c.Dictionary())
		if err != nil {
			t.Fatal(err)
		}
		m = decoded
		if len(m.UnknownMandatoryAVPs()) != 1 {
			t.Fatal("unknown mandatory AVP was not decoded")
		}
	}
	var me *diam.MessageError
	switch description {
	case "missing":
		me = &diam.MessageError{ResultCode: diam.MissingAVP}
	case "invalid-length":
		me = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
	case "failed-length":
		me = &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("synthetic"))}
	case "fatal":
		me = &diam.MessageError{ResultCode: diam.UnsupportedVersion, Fatal: true}
	case "protocol":
		me = &diam.MessageError{ResultCode: diam.CommandUnsupported}
	}
	err := sm.HandleMessageError(c, m, me)
	var replies []string
	for len(c.writes) > 0 {
		a, e := diam.ReadMessage(bytes.NewReader(<-c.writes), c.Dictionary())
		if e != nil {
			t.Fatal(e)
		}
		var failed []uint32
		if f, e := a.FindAVP(avp.FailedAVP, 0); e == nil {
			for _, child := range f.Data.(*diam.GroupedAVP).AVP {
				failed = append(failed, child.Code)
			}
		}
		replies = append(replies, fmt.Sprintf("%d/%x/%v", protocolAnswerCode(a), a.Header.CommandFlags, failed))
	}
	var texts []string
	for _, r := range logs.Records()[beforeLogs:] {
		texts = append(texts, r.Message)
		if r.Message == "sm: error answer failed" && command == 9999 {
			want := "required Diameter reply could not be built"
			if admission == "manual" {
				want = fmt.Sprintf("cannot form valid Diameter error answer: Diameter validation failed (3001): application %d: command code 9999: dictionary entry not found", app)
			}
			cause, _ := logtest.Attr(r, "error").Any().(error)
			if cause == nil || cause.Error() != want {
				t.Fatalf("error reply construction cause=%v, want %s", cause, want)
			}
		}
	}
	got := fmt.Sprintf("err=%v closed=%t replies=%v events=%v logs=%v", err, c.Closed(), replies, events, texts)
	c.Close()
	return got
}

// Decoder reports take precedence over semantic validation, while unsupported
// applications and mandatory AVPs retain their configured rejection priority.
func TestMessageErrorValidationPrecedence(t *testing.T) {
	tests := []struct{ admission, scenario, description, want string }{
		{"manual", "default", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "default", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"manual", "default", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"manual", "default", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"manual", "default", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "default", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"manual", "supported", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "supported", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"manual", "supported", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"manual", "supported", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"manual", "supported", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "supported", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"manual", "unsupported", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "unsupported", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported", "invalid-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "unsupported", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unknown-command", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "unknown-command", "missing", "err=<nil> closed=true replies=[] events=[malformed_message/5005/true/3] logs=[sm: error answer failed]"},
		{"manual", "unknown-command", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"manual", "unknown-command", "failed-length", "err=<nil> closed=true replies=[] events=[malformed_message/5014/true/3] logs=[sm: error answer failed]"},
		{"manual", "unknown-command", "fatal", "err=<nil> closed=true replies=[] events=[malformed_message/5011/true/3] logs=[sm: error answer failed]"},
		{"manual", "unknown-command", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"manual", "unsupported-command", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "unsupported-command", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-command", "invalid-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-command", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-command", "fatal", "err=<nil> closed=true replies=[] events=[malformed_message/5011/true/3] logs=[sm: error answer failed]"},
		{"manual", "unsupported-command", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "mandatory", "missing", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[]"},
		{"manual", "mandatory", "invalid-length", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[]"},
		{"manual", "mandatory", "failed-length", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[]"},
		{"manual", "mandatory", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "mandatory", "protocol", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[]"},
		{"manual", "unsupported-mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "unsupported-mandatory", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-mandatory", "invalid-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-mandatory", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "unsupported-mandatory", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "unsupported-mandatory", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[]"},
		{"manual", "relay-mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "relay-mandatory", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"manual", "relay-mandatory", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"manual", "relay-mandatory", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"manual", "relay-mandatory", "fatal", "err=<nil> closed=false replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"manual", "relay-mandatory", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"native", "default", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "default", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"native", "default", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "default", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"native", "default", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "default", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"native", "supported", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "supported", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"native", "supported", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "supported", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"native", "supported", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "supported", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"native", "unsupported", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "unsupported", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unknown-command", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "unknown-command", "missing", "err=<nil> closed=true replies=[] events=[malformed_message/5005/true/3] logs=[sm: error answer failed]"},
		{"native", "unknown-command", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "unknown-command", "failed-length", "err=<nil> closed=true replies=[] events=[malformed_message/5014/true/3] logs=[sm: error answer failed]"},
		{"native", "unknown-command", "fatal", "err=<nil> closed=true replies=[] events=[malformed_message/5011/true/3] logs=[sm: error answer failed]"},
		{"native", "unknown-command", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
		{"native", "unsupported-command", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported-command", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported-command", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported-command", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported-command", "fatal", "err=<nil> closed=true replies=[] events=[malformed_message/5011/true/3] logs=[sm: error answer failed]"},
		{"native", "unsupported-command", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "mandatory", "missing", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[sm: unsupported mandatory AVP]"},
		{"native", "mandatory", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "mandatory", "failed-length", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[sm: unsupported mandatory AVP]"},
		{"native", "mandatory", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "mandatory", "protocol", "err=<nil> closed=false replies=[5001/40/[65244]] events=[unsupported_avp/5001/false/2] logs=[sm: unsupported mandatory AVP]"},
		{"native", "unsupported-mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported-mandatory", "missing", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported-mandatory", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "unsupported-mandatory", "failed-length", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "unsupported-mandatory", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "unsupported-mandatory", "protocol", "err=<nil> closed=false replies=[3007/60/[]] events=[unsupported_application/3007/false/2] logs=[sm: unsupported command answered]"},
		{"native", "relay-mandatory", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "relay-mandatory", "missing", "err=<nil> closed=false replies=[5005/40/[]] events=[malformed_message/5005/false/2] logs=[]"},
		{"native", "relay-mandatory", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "relay-mandatory", "failed-length", "err=<nil> closed=false replies=[5014/40/[263]] events=[malformed_message/5014/false/2] logs=[]"},
		{"native", "relay-mandatory", "fatal", "err=<nil> closed=true replies=[5011/40/[]] events=[malformed_message/5011/true/2] logs=[]"},
		{"native", "relay-mandatory", "protocol", "err=<nil> closed=false replies=[3001/60/[]] events=[malformed_message/3001/false/2] logs=[]"},
	}
	for _, tc := range tests {
		t.Run(tc.admission+"/"+tc.scenario+"/"+tc.description, func(t *testing.T) {
			if got := observeMessageErrorPrecedence(t, tc.admission, tc.scenario, tc.description); got != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}
