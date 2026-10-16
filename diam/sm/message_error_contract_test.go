package sm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type messageErrorContractConn struct {
	*handshakeConn
	logger *slog.Logger
}

func (c *messageErrorContractConn) Logger() *slog.Logger { return c.logger }

// Error reports retain separate API errors, reply obligations, observations and
// transport ownership for manual admission and native CER admission.
func TestAdmittedMessageErrorContract(t *testing.T) {
	tests := []struct{ admission, shape, description, want string }{
		{"manual", "request", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "request", "missing", "err=<nil> closed=false replies=[5005] events=[malformed_message/5005/close=false/reply=2/5005] logs=[]"},
		{"manual", "request", "fatal-version", "err=<nil> closed=false replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"manual", "request", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"manual", "answer", "nil", "err=<nil> closed=false replies=[] events=[malformed_message/0/close=false/reply=0/0] logs=[]"},
		{"manual", "answer", "missing", "err=<nil> closed=false replies=[] events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"manual", "answer", "fatal-version", "err=<nil> closed=false replies=[] events=[malformed_message/5011/close=true/reply=0/0] logs=[]"},
		{"manual", "answer", "invalid-length", "err=<nil> closed=false replies=[] events=[malformed_message/5014/close=false/reply=0/0] logs=[]"},
		{"manual", "CER", "nil", "err=<nil> closed=false replies=[] events=[unexpected_message/0/close=false/reply=0/0] logs=[sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible]"},
		{"manual", "CER", "missing", "err=<nil> closed=false replies=[] events=[unexpected_message/0/close=false/reply=0/0] logs=[sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible]"},
		{"manual", "CER", "fatal-version", "err=<nil> closed=false replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"manual", "CER", "invalid-length", "err=<nil> closed=false replies=[] events=[unexpected_message/0/close=false/reply=0/0] logs=[sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible]"},
		{"manual", "appCER", "nil", "err=<nil> closed=true replies=[3008] events=[invalid_header/3008/close=true/reply=2/3008] logs=[sm: rejected CER; closing connection]"},
		{"manual", "appCER", "missing", "err=<nil> closed=true replies=[3008] events=[invalid_header/3008/close=true/reply=2/3008] logs=[sm: rejected CER; closing connection]"},
		{"manual", "appCER", "fatal-version", "err=<nil> closed=true replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[sm: rejected CER; closing connection]"},
		{"manual", "appCER", "invalid-length", "err=<nil> closed=true replies=[3008] events=[invalid_header/3008/close=true/reply=2/3008] logs=[sm: rejected CER; closing connection]"},
		{"manual", "nil", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"manual", "nil", "missing", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"manual", "nil", "fatal-version", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"manual", "nil", "invalid-length", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"manual", "headerless", "nil", "err=<nil> closed=false replies=[] events=[malformed_message/0/close=false/reply=0/0] logs=[]"},
		{"manual", "headerless", "missing", "err=<nil> closed=false replies=[] events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"manual", "headerless", "fatal-version", "err=<nil> closed=false replies=[] events=[malformed_message/5011/close=true/reply=0/0] logs=[]"},
		{"manual", "headerless", "invalid-length", "err=<nil> closed=false replies=[] events=[malformed_message/5014/close=false/reply=0/0] logs=[]"},
		{"manual", "invalid-header", "nil", "err=<nil> closed=false replies=[3008] events=[invalid_header/3008/close=false/reply=2/3008] logs=[]"},
		{"manual", "invalid-header", "missing", "err=<nil> closed=false replies=[3008] events=[invalid_header/3008/close=false/reply=2/3008] logs=[]"},
		{"manual", "invalid-header", "fatal-version", "err=<nil> closed=false replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"manual", "invalid-header", "invalid-length", "err=<nil> closed=false replies=[3008] events=[invalid_header/3008/close=false/reply=2/3008] logs=[]"},
		{"manual", "invalid-answer", "nil", "err=<nil> closed=false replies=[] events=[invalid_header/3008/close=false/reply=0/0] logs=[]"},
		{"manual", "invalid-answer", "missing", "err=<nil> closed=false replies=[] events=[invalid_header/3008/close=false/reply=0/0] logs=[]"},
		{"manual", "invalid-answer", "fatal-version", "err=<nil> closed=false replies=[] events=[malformed_message/5011/close=true/reply=0/0] logs=[]"},
		{"manual", "invalid-answer", "invalid-length", "err=<nil> closed=false replies=[] events=[invalid_header/3008/close=false/reply=0/0] logs=[]"},
		{"native", "request", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "request", "missing", "err=<nil> closed=false replies=[5005] events=[malformed_message/5005/close=false/reply=2/5005] logs=[]"},
		{"native", "request", "fatal-version", "err=<nil> closed=true replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"native", "request", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "answer", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "answer", "missing", "err=<nil> closed=false replies=[] events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"native", "answer", "fatal-version", "err=<nil> closed=true replies=[] events=[malformed_message/5011/close=true/reply=0/0] logs=[]"},
		{"native", "answer", "invalid-length", "err=<nil> closed=false replies=[] events=[malformed_message/5014/close=false/reply=0/0] logs=[]"},
		{"native", "CER", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "CER", "missing", "err=<nil> closed=false replies=[] events=[unexpected_message/0/close=false/reply=0/0] logs=[sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible]"},
		{"native", "CER", "fatal-version", "err=<nil> closed=true replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"native", "CER", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "appCER", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "appCER", "missing", "err=<nil> closed=true replies=[3008] events=[invalid_header/3008/close=true/reply=2/3008] logs=[sm: invalid message header sm: rejected CER; closing connection]"},
		{"native", "appCER", "fatal-version", "err=<nil> closed=true replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[sm: rejected CER; closing connection]"},
		{"native", "appCER", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "nil", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "nil", "missing", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "nil", "fatal-version", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "nil", "invalid-length", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "headerless", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "headerless", "missing", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "headerless", "fatal-version", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "headerless", "invalid-length", "err=<nil> closed=true replies=[] events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "invalid-header", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "invalid-header", "missing", "err=<nil> closed=false replies=[3008] events=[invalid_header/3008/close=false/reply=2/3008] logs=[sm: invalid message header]"},
		{"native", "invalid-header", "fatal-version", "err=<nil> closed=true replies=[5011] events=[malformed_message/5011/close=true/reply=2/5011] logs=[]"},
		{"native", "invalid-header", "invalid-length", "err=diameter result code 5014 requires Failed-AVP closed=false replies=[] events=[] logs=[]"},
		{"native", "invalid-answer", "nil", "err=cannot answer a nil Diameter message error closed=false replies=[] events=[] logs=[]"},
		{"native", "invalid-answer", "missing", "err=<nil> closed=false replies=[] events=[invalid_header/3008/close=false/reply=0/0] logs=[sm: invalid message header]"},
		{"native", "invalid-answer", "fatal-version", "err=<nil> closed=true replies=[] events=[malformed_message/5011/close=true/reply=0/0] logs=[]"},
		{"native", "invalid-answer", "invalid-length", "err=<nil> closed=false replies=[] events=[invalid_header/3008/close=false/reply=0/0] logs=[sm: invalid message header]"},
	}
	for _, tc := range tests {
		t.Run(tc.admission+"/"+tc.shape+"/"+tc.description, func(t *testing.T) {
			logs := logtest.New()
			c := &messageErrorContractConn{handshakeConn: newHandshakeConn(), logger: logs.Logger()}
			cfg := testMessageErrorSettings(c.Dictionary())
			cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
			var events []string
			var cerCalls, ceaCalls, handshakes int
			cfg.OnCER = func(diam.Conn, *diam.Message) { cerCalls++ }
			cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaCalls++ }
			cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes++ }
			cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				events = append(events, fmt.Sprintf("%s/%d/close=%t/reply=%d/%d", e.Err.Kind(), e.Err.ResultCode(), e.Closing, e.Reply, e.ReplyCode))
			}
			sm := mustNewStateMachine(t, cfg, c.Dictionary())
			if tc.admission == "manual" {
				replaceAdmission(c, "CEA")
			} else {
				cleanup := sm.HandleAccept(c)
				defer cleanup()
				sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), 1001))
				<-c.writes
			}
			cerCalls, ceaCalls, handshakes = 0, 0, 0
			events = nil
			beforeLogs := len(logs.Records())
			m := regressionDWR(t)
			switch tc.shape {
			case "answer":
				m.Header.CommandFlags = 0
			case "CER":
				m = regressionCER(t, c.Dictionary(), 1001)
			case "appCER":
				m = regressionCER(t, c.Dictionary(), 1001)
				m.Header.ApplicationID = 1001
			case "nil":
				m = nil
			case "headerless":
				m = &diam.Message{}
			case "invalid-header":
				m.Header.CommandFlags |= diam.ErrorFlag
			case "invalid-answer":
				m.Header.CommandFlags = diam.RetransmittedFlag
			}
			var me *diam.MessageError
			switch tc.description {
			case "missing":
				me = &diam.MessageError{ResultCode: diam.MissingAVP}
			case "fatal-version":
				me = &diam.MessageError{ResultCode: diam.UnsupportedVersion, Fatal: true}
			case "invalid-length":
				me = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
			}
			err := sm.HandleMessageError(c, m, me)
			var replies []uint32
			for len(c.writes) != 0 {
				answer, readErr := diam.ReadMessage(bytes.NewReader(<-c.writes), c.Dictionary())
				if readErr != nil {
					t.Fatal(readErr)
				}
				replies = append(replies, protocolAnswerCode(answer))
			}
			var texts []string
			for _, record := range logs.Records()[beforeLogs:] {
				texts = append(texts, record.Message)
			}
			got := fmt.Sprintf("err=%v closed=%t replies=%v events=%v logs=%v", err, c.Closed(), replies, events, texts)
			if got != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
			wantCEA := 0
			if tc.shape == "CER" || tc.shape == "appCER" {
				wantCEA = len(replies)
			}
			if cerCalls != 0 || handshakes != 0 || ceaCalls != wantCEA {
				t.Fatalf("error report callbacks CER/CEA/handshake=%d/%d/%d, want 0/%d/0", cerCalls, ceaCalls, handshakes, wantCEA)
			}
			if tc.admission == "manual" && tc.shape == "appCER" && me != nil && me.Fatal {
				record := logs.Records()[beforeLogs]
				cause, _ := logtest.Attr(record, "error").Any().(error)
				if cause == nil || !strings.Contains(cause.Error(), me.Error()) {
					t.Fatalf("rejected CER log lost original error: %v", cause)
				}
			}
			c.Close()
		})
	}
}

func TestRevokedAdmissionRejectsNilErrorDescription(t *testing.T) {
	for _, shape := range []string{"request", "answer", "CER", "nil", "headerless", "invalid-header"} {
		t.Run(shape, func(t *testing.T) {
			c := &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})}
			defer c.Close()
			replaceAdmission(c, "CEA")
			sm := mustNewStateMachine(t, testMessageErrorSettings(c.Dictionary()), c.Dictionary())
			prime := diam.NewMessage(0xeeff, 0, 0, 17, 18, c.Dictionary())
			sm.HandleIdx(diam.CommandIndex{Code: 0xeeff}, diam.HandlerFunc(func(diam.Conn, *diam.Message) {}))
			sm.ServeDIAM(c, prime)
			c.SetContext(context.Background())
			m := regressionDWR(t)
			switch shape {
			case "answer":
				m.Header.CommandFlags = 0
			case "CER":
				m = regressionCER(t, c.Dictionary(), 1001)
			case "nil":
				m = nil
			case "headerless":
				m = &diam.Message{}
			case "invalid-header":
				m.Header.CommandFlags |= diam.ErrorFlag
			}
			err := sm.HandleMessageError(c, m, nil)
			if err == nil || !strings.Contains(err.Error(), "nil Diameter message error") || c.Closed() || len(c.writes) != 0 {
				t.Fatalf("revoked claims bypassed nil-description validation: error=%v closed=%t writes=%d", err, c.Closed(), len(c.writes))
			}
		})
	}
}

func TestRejectedExternalCERLogPreservesOriginalError(t *testing.T) {
	logs := logtest.New()
	c := &messageErrorContractConn{handshakeConn: newHandshakeConn(), logger: logs.Logger()}
	replaceAdmission(c, "CEA")
	sm := mustNewStateMachine(t, testMessageErrorSettings(c.Dictionary()), c.Dictionary())
	m := regressionCER(t, c.Dictionary(), 1001)
	m.Header.ApplicationID = 1001
	cause := errors.New("synthetic framing cause")
	me := &diam.MessageError{ResultCode: diam.UnsupportedVersion, Fatal: true, Err: cause}
	if err := sm.HandleMessageError(c, m, me); err != nil {
		t.Fatal(err)
	}
	records := logs.Records()
	if len(records) != 1 || records[0].Message != "sm: rejected CER; closing connection" {
		t.Fatalf("unexpected rejection logs: %v", records)
	}
	logged, _ := logtest.Attr(records[0], "error").Any().(error)
	if !errors.Is(logged, me) || !errors.Is(logged, cause) {
		t.Fatalf("rejection log lost the original error chain: %v", logged)
	}
	c.Close()
}

type messageErrorOrderedConn struct {
	*messageErrorContractConn
	beforeWrite func()
}

func (c *messageErrorOrderedConn) Write(b []byte) (int, error) {
	c.beforeWrite()
	return c.messageErrorContractConn.Write(b)
}
func (c *messageErrorOrderedConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }

func TestRejectedExternalCERWarningFollowsReply(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			logs := logtest.New()
			c := &messageErrorOrderedConn{messageErrorContractConn: &messageErrorContractConn{handshakeConn: newHandshakeConn(), logger: logs.Logger()}}
			replaceAdmission(c, "CEA")
			var order []string
			cfg := testMessageErrorSettings(c.Dictionary())
			cfg.OnCEA = func(diam.Conn, *diam.Message) {
				order = append(order, "OnCEA")
				if len(logs.Records()) != 0 || c.Closed() {
					t.Fatal("warning or closure preceded OnCEA")
				}
			}
			c.beforeWrite = func() {
				order = append(order, "write")
				if len(logs.Records()) != 0 || c.Closed() {
					t.Fatal("warning or closure preceded reply write")
				}
			}
			c.afterClose = func() {
				order = append(order, "close")
				var texts []string
				for _, r := range logs.Records() {
					texts = append(texts, r.Message)
				}
				want := []string{"sm: rejected CER; closing connection"}
				if failed {
					want = []string{"sm: error answer failed"}
				}
				if !slices.Equal(texts, want) {
					t.Fatalf("warning did not precede closure after reply: %v", texts)
				}
			}
			cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				order = append(order, "observer")
				want := diam.ProtocolReplyWritten
				if failed {
					want = diam.ProtocolReplyFailed
				}
				if !c.Closed() || !e.Closing || e.Reply != want {
					t.Fatalf("observer preceded rejection completion: %+v", e)
				}
			}
			if failed {
				c.writeErr = errors.New("synthetic error reply write failure")
			}
			sm := mustNewStateMachine(t, cfg, c.Dictionary())
			m := regressionCER(t, c.Dictionary(), 1001)
			m.Header.ApplicationID = 1001
			if err := sm.HandleMessageError(c, m, &diam.MessageError{ResultCode: diam.UnsupportedVersion, Fatal: true}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(order, []string{"OnCEA", "write", "close", "observer"}) {
				t.Fatalf("rejection callbacks=%v", order)
			}
		})
	}
}
