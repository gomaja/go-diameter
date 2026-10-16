package sm

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type messageErrorLifecycleConn struct {
	*messageErrorContractConn
	done chan struct{}
	once sync.Once
}

func (c *messageErrorLifecycleConn) CloseNotify() <-chan struct{} { return c.done }
func (c *messageErrorLifecycleConn) Close() {
	c.once.Do(func() { c.messageErrorContractConn.Close(); close(c.done) })
}

// Transport closure and the Closing gate precede external API diagnostics;
// native admission retains its error-description validation contract.
func TestMessageErrorTerminalPrecedence(t *testing.T) {
	tests := []struct{ admission, stage, shape, description, want string }{
		{"manual", "closed", "DWR", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "DWR", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "DWR", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "DPR", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "DPR", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "DPR", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "CER", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "CER", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "CER", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-request", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-request", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-request", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-answer", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-answer", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "app-answer", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "nil", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "nil", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "nil", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "headerless", "nil", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "headerless", "missing", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closed", "headerless", "length", "err=<nil> closed=true writes=0 events=[] logs=[]"},
		{"manual", "closing", "DWR", "nil", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "DWR", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "DWR", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "DPR", "nil", "err=<nil> closed=false writes=0 events=[malformed_message/0/close=false/reply=0/0] logs=[]"},
		{"manual", "closing", "DPR", "missing", "err=<nil> closed=false writes=0 events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"manual", "closing", "DPR", "length", "err=<nil> closed=false writes=0 events=[malformed_message/5014/close=false/reply=0/0] logs=[]"},
		{"manual", "closing", "CER", "nil", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "CER", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "CER", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-request", "nil", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-request", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-request", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-answer", "nil", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-answer", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "app-answer", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "nil", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "nil", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"manual", "closing", "nil", "length", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"manual", "closing", "headerless", "nil", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "headerless", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"manual", "closing", "headerless", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closed", "DWR", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "DWR", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/5005/close=true/reply=3/5005] logs=[]"},
		{"native", "closed", "DWR", "length", "err=diameter result code 5014 requires Failed-AVP closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "DPR", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "DPR", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/5005/close=true/reply=3/5005] logs=[]"},
		{"native", "closed", "DPR", "length", "err=diameter result code 5014 requires Failed-AVP closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "CER", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "CER", "missing", "err=<nil> closed=true writes=0 events=[unexpected_message/0/close=false/reply=0/0] logs=[sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible]"},
		{"native", "closed", "CER", "length", "err=diameter result code 5014 requires Failed-AVP closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "app-request", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "app-request", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/5005/close=true/reply=3/5005] logs=[sm: error answer failed]"},
		{"native", "closed", "app-request", "length", "err=diameter result code 5014 requires Failed-AVP closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "app-answer", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "app-answer", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"native", "closed", "app-answer", "length", "err=<nil> closed=true writes=0 events=[malformed_message/5014/close=false/reply=0/0] logs=[]"},
		{"native", "closed", "nil", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "nil", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "closed", "nil", "length", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "closed", "headerless", "nil", "err=cannot answer a nil Diameter message error closed=true writes=0 events=[] logs=[]"},
		{"native", "closed", "headerless", "missing", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "closed", "headerless", "length", "err=<nil> closed=true writes=0 events=[malformed_message/0/close=true/reply=0/0] logs=[]"},
		{"native", "closing", "DWR", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "DWR", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "DWR", "length", "err=diameter result code 5014 requires Failed-AVP closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "DPR", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "DPR", "missing", "err=<nil> closed=false writes=0 events=[malformed_message/5005/close=false/reply=0/0] logs=[]"},
		{"native", "closing", "DPR", "length", "err=diameter result code 5014 requires Failed-AVP closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "CER", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "CER", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "CER", "length", "err=diameter result code 5014 requires Failed-AVP closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-request", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-request", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-request", "length", "err=diameter result code 5014 requires Failed-AVP closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-answer", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-answer", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "app-answer", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "nil", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "nil", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "nil", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "headerless", "nil", "err=cannot answer a nil Diameter message error closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "headerless", "missing", "err=<nil> closed=false writes=0 events=[] logs=[]"},
		{"native", "closing", "headerless", "length", "err=<nil> closed=false writes=0 events=[] logs=[]"},
	}
	for _, tc := range tests {
		t.Run(tc.admission+"/"+tc.stage+"/"+tc.shape+"/"+tc.description, func(t *testing.T) {
			logs := logtest.New()
			baseConn := &messageErrorContractConn{newHandshakeConn(), logs.Logger()}
			var c diam.Conn = baseConn
			var closingConn *messageErrorLifecycleConn
			if tc.stage == "closing" {
				closingConn = &messageErrorLifecycleConn{messageErrorContractConn: baseConn, done: make(chan struct{})}
				c = closingConn
			}
			cfg := testMessageErrorSettings(c.Dictionary())
			cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
			var events []string
			cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				events = append(events, fmt.Sprintf("%s/%d/close=%t/reply=%d/%d", e.Err.Kind(), e.Err.ResultCode(), e.Closing, e.Reply, e.ReplyCode))
			}
			sm := mustNewStateMachine(t, cfg, c.Dictionary())
			if tc.admission == "manual" {
				c.SetContext(smpeer.NewContext(context.Background(), admissionMetadata("CEA")))
				sm.HandleIdx(diam.CommandIndex{Code: 9999}, diam.HandlerFunc(func(diam.Conn, *diam.Message) {}))
				sm.ServeDIAM(c, diam.NewMessage(9999, 0, 0, 1, 2, c.Dictionary()))
			} else {
				cleanup := sm.HandleAccept(c)
				defer cleanup()
				sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), 1001))
				<-baseConn.writes
			}
			var disconnectDone chan error
			if tc.stage == "closed" {
				c.Close()
			} else {
				disconnectDone = make(chan error, 1)
				go func() { disconnectDone <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
				select {
				case <-baseConn.writes:
				case e := <-disconnectDone:
					t.Fatalf("disconnect beforeDPR %v", e)
				case <-time.After(time.Second):
					t.Fatal("DPR missing")
				}
			}
			events = nil
			before := len(logs.Records())
			m := regressionDWR(t)
			switch tc.shape {
			case "DPR":
				m.Header.CommandCode = diam.DisconnectPeer
			case "CER":
				m = regressionCER(t, c.Dictionary(), 1001)
			case "app-request":
				m = diam.NewMessage(9999, diam.RequestFlag, 9999, 1, 2, c.Dictionary())
			case "app-answer":
				m = diam.NewMessage(9999, 0, 9999, 1, 2, c.Dictionary())
			case "nil":
				m = nil
			case "headerless":
				m = &diam.Message{}
			}
			var me *diam.MessageError
			switch tc.description {
			case "missing":
				me = &diam.MessageError{ResultCode: diam.MissingAVP}
			case "length":
				me = &diam.MessageError{ResultCode: diam.InvalidAVPLength}
			}
			err := sm.HandleMessageError(c, m, me)
			var texts []string
			for _, r := range logs.Records()[before:] {
				texts = append(texts, r.Message)
			}
			got := fmt.Sprintf("err=%v closed=%t writes=%d events=%v logs=%v", err, c.Closed(), len(baseConn.writes), events, texts)
			if got != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
			c.Close()
			if disconnectDone != nil {
				select {
				case <-disconnectDone:
				case <-time.After(time.Second):
					t.Fatal("disconnect notjoined")
				}
			}
		})
	}
}
