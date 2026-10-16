package sm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type errorDispositionConn struct {
	*handshakeConn
	logger *slog.Logger
	done   chan struct{}
	once   sync.Once
}

func (c *errorDispositionConn) Logger() *slog.Logger         { return c.logger }
func (c *errorDispositionConn) CloseNotify() <-chan struct{} { return c.done }
func (c *errorDispositionConn) Close()                       { c.once.Do(func() { c.handshakeConn.Close(); close(c.done) }) }

var errorDispositionShapes = []string{
	"nil", "headerless", "DWR", "DWA", "invalid-DWR", "invalid-DWA", "app-DWR", "app-DWA",
	"CER", "CEA", "invalid-CER", "invalid-CEA", "app-CER", "app-CEA",
	"DPR", "DPA", "invalid-DPR", "invalid-DPA", "app-request", "app-answer",
}

var errorDispositionDescriptions = []string{
	"nil", "missing", "fatal-missing", "protocol", "fatal-protocol", "invalid-value", "fatal-invalid-value",
	"version", "fatal-version", "message-length", "fatal-message-length", "avp-length", "fatal-avp-length",
	"failed-avp-length", "fatal-failed-avp-length",
}

type errorDispositionContract struct {
	Descriptions []string         `json:"descriptions"`
	Outcomes     []string         `json:"outcomes"`
	Cases        map[string][]int `json:"cases"`
}

// Error-report disposition preserves the API error, transport ownership, reply,
// observer report, logs and callbacks for every admission and lifecycle phase.
func TestMessageErrorAdmissionDisposition(t *testing.T) {
	data, err := os.ReadFile("testdata/message_error_disposition.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract errorDispositionContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(contract.Descriptions, errorDispositionDescriptions) {
		t.Fatal("contract description columns do not match")
	}
	if len(contract.Cases) != 2*3*len(errorDispositionShapes) {
		t.Fatalf("contract has %d rows", len(contract.Cases))
	}
	for _, admission := range []string{"manual", "native"} {
		for _, stage := range []string{"open", "closing", "closed"} {
			for _, shape := range errorDispositionShapes {
				key := strings.Join([]string{admission, stage, shape}, "/")
				wants, ok := contract.Cases[key]
				if !ok || len(wants) != len(errorDispositionDescriptions) {
					t.Fatalf("missing descriptions for %s", key)
				}
				for i, description := range errorDispositionDescriptions {
					t.Run(key+"/"+description, func(t *testing.T) {
						if wants[i] < 0 || wants[i] >= len(contract.Outcomes) {
							t.Fatalf("invalid outcome %d", wants[i])
						}
						got := observeErrorDisposition(t, admission, stage, shape, description)
						if want := contract.Outcomes[wants[i]]; got != want {
							t.Fatalf("got  %s\nwant %s", got, want)
						}
					})
				}
			}
		}
	}
}

func observeErrorDisposition(t *testing.T, admission, stage, shape, description string) string {
	t.Helper()
	logs := logtest.New()
	c := &errorDispositionConn{handshakeConn: newHandshakeConn(), logger: logs.Logger(), done: make(chan struct{})}
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
	var cleanup func()
	if admission == "manual" {
		metadata := &smpeer.Metadata{OriginHost: "saved.example", OriginRealm: "example", Applications: []uint32{1001}, CEA: &smparser.CEA{}}
		c.SetContext(smpeer.NewContext(context.Background(), metadata))
		if stage != "open" {
			sm.HandleIdx(diam.CommandIndex{Code: 9999}, diam.HandlerFunc(func(diam.Conn, *diam.Message) {}))
			sm.ServeDIAM(c, diam.NewMessage(9999, 0, 0, 1, 2, c.Dictionary()))
		}
	} else {
		cleanup = sm.HandleAccept(c)
		sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), 1001))
		select {
		case <-c.writes:
		case <-time.After(time.Second):
			t.Fatal("initial CEA missing")
		}
	}
	var disconnectDone chan error
	t.Cleanup(func() {
		c.Close()
		if disconnectDone != nil {
			select {
			case <-disconnectDone:
			case <-time.After(time.Second):
				t.Error("disconnect did not finish")
			}
		}
		if cleanup != nil {
			cleanup()
		}
	})
	switch stage {
	case "closed":
		c.Close()
	case "closing":
		disconnectDone = make(chan error, 1)
		go func() { disconnectDone <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
		select {
		case <-c.writes:
		case err := <-disconnectDone:
			t.Fatalf("disconnect before DPR: %v", err)
		case <-time.After(time.Second):
			t.Fatal("DPR missing")
		}
	}
	events = nil
	cerCalls, ceaCalls, handshakes = 0, 0, 0
	beforeLogs := len(logs.Records())
	m := errorDispositionMessage(t, c, shape)
	me := errorDispositionDescription(description)
	var original *diam.MessageError
	if me != nil {
		copy := *me
		original = &copy
	}
	var originalHeader *diam.Header
	if m != nil && m.Header != nil {
		copy := *m.Header
		originalHeader = &copy
	}
	err := sm.HandleMessageError(c, m, me)
	if me != nil && (me.ResultCode != original.ResultCode || me.Fatal != original.Fatal || me.FailedAVP != original.FailedAVP || me.Err != original.Err) {
		t.Fatal("error description mutated")
	}
	if originalHeader != nil && *m.Header != *originalHeader {
		t.Fatal("message header mutated")
	}
	var replies []string
	for len(c.writes) != 0 {
		answer, readErr := diam.ReadMessage(bytes.NewReader(<-c.writes), c.Dictionary())
		if readErr != nil {
			t.Fatal(readErr)
		}
		var failed []uint32
		if f, findErr := answer.FindAVP(avp.FailedAVP, 0); findErr == nil {
			for _, child := range f.Data.(*diam.GroupedAVP).AVP {
				failed = append(failed, child.Code)
			}
		}
		replies = append(replies, fmt.Sprintf("%d/%d/%x/%v", answer.Header.CommandCode, protocolAnswerCode(answer), answer.Header.CommandFlags, failed))
	}
	var texts []string
	for _, record := range logs.Records()[beforeLogs:] {
		texts = append(texts, record.Message)
	}
	return fmt.Sprintf("err=%v closed=%t replies=%v events=%v logs=%v callbacks=%d/%d/%d", err, c.Closed(), replies, events, texts, cerCalls, ceaCalls, handshakes)
}

func errorDispositionMessage(t *testing.T, c diam.Conn, shape string) *diam.Message {
	t.Helper()
	if shape == "nil" {
		return nil
	}
	if shape == "headerless" {
		return &diam.Message{}
	}
	m := regressionDWR(t)
	switch {
	case strings.HasSuffix(shape, "CER"), strings.HasSuffix(shape, "CEA"):
		m = regressionCER(t, c.Dictionary(), 1001)
	case strings.HasSuffix(shape, "DPR"), strings.HasSuffix(shape, "DPA"):
		m.Header.CommandCode = diam.DisconnectPeer
	case strings.HasPrefix(shape, "app-") && slices.Contains([]string{"app-request", "app-answer"}, shape):
		m = diam.NewMessage(9999, diam.RequestFlag, 9999, 1, 2, c.Dictionary())
	}
	if strings.HasSuffix(shape, "A") || shape == "app-answer" {
		m.Header.CommandFlags = 0
	}
	if strings.HasPrefix(shape, "invalid-") {
		if m.Header.CommandFlags&diam.RequestFlag != 0 {
			m.Header.CommandFlags |= diam.ErrorFlag
		} else {
			m.Header.CommandFlags |= diam.RetransmittedFlag
		}
	}
	if strings.HasPrefix(shape, "app-") && shape != "app-request" && shape != "app-answer" {
		m.Header.ApplicationID = 1001
	}
	return m
}

func errorDispositionDescription(description string) *diam.MessageError {
	if description == "nil" {
		return nil
	}
	me := &diam.MessageError{Fatal: strings.HasPrefix(description, "fatal-")}
	switch strings.TrimPrefix(description, "fatal-") {
	case "missing":
		me.ResultCode = diam.MissingAVP
	case "protocol":
		me.ResultCode = diam.CommandUnsupported
	case "invalid-value":
		me.ResultCode = diam.InvalidAVPValue
	case "version":
		me.ResultCode = diam.UnsupportedVersion
	case "message-length":
		me.ResultCode = diam.InvalidMessageLength
	case "avp-length":
		me.ResultCode = diam.InvalidAVPLength
	case "failed-avp-length":
		me.ResultCode = diam.InvalidAVPLength
		me.FailedAVP = diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("synthetic"))
	}
	return me
}
