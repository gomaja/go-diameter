package sm

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// A caller-supplied message dictionary can decode a valid base request while
// lacking the answer grammar, or forbid flags needed by the answer builder.
func rejectionConstructionDictionary(t *testing.T, forbidOriginM bool) *dict.Parser {
	t.Helper()
	p, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	originFlags := `must="M"`
	if forbidOriginM {
		originFlags = `must-not="M"`
	}
	err = p.Load(strings.NewReader(`<diameter><application id="0">
<avp name="Origin-Host" code="264" ` + originFlags + `><data type="DiameterIdentity"/></avp>
<avp name="Origin-Realm" code="296" must="M"><data type="DiameterIdentity"/></avp>
<avp name="Origin-State-Id" code="278" must="M"><data type="Unsigned32"/></avp>
<avp name="Disconnect-Cause" code="273" must="M"><data type="Enumerated"/></avp>
<avp name="Result-Code" code="268" must="M"><data type="Unsigned32"/></avp>
<avp name="Failed-AVP" code="279" must="M"><data type="Grouped"><rule avp="AVP"/></data></avp>
</application></diameter>`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeRejectionRequest(t *testing.T, m *diam.Message, dictionary *dict.Parser) *diam.Message {
	t.Helper()
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

type rejectionConstructionPeer struct {
	sm     *StateMachine
	conn   diam.Conn
	wire   *finalDPATransport
	logs   *logtest.Recorder
	events chan diam.ProtocolErrorEvent
}

// Both adapters use their production reader and admission path. Synthetic
// channel transport makes the disconnect deadline independent of scheduling.
func newRejectionConstructionPeer(t *testing.T, role string) *rejectionConstructionPeer {
	t.Helper()
	dictionary := newSMTestDictionary(dict.Base())
	p := &rejectionConstructionPeer{
		wire: &finalDPATransport{reads: make(chan finalDPARead, 8), writes: make(chan *diam.Message, 8), closed: make(chan struct{}), eofRead: make(chan struct{})},
		logs: logtest.New(), events: make(chan diam.ProtocolErrorEvent, 8),
	}
	cfg := testMessageErrorSettings(dictionary)
	cfg.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
	cfg.RejectUnknownMandatoryAVPs = true
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	p.sm = mustNewStateMachine(t, cfg, dictionary)
	if role == "accepted" {
		server := &diam.Server{Handler: p.sm, Dict: dictionary, Logger: p.logs.Logger()}
		var err error
		p.conn, err = server.NewConn(p.wire)
		if err != nil {
			t.Fatal(err)
		}
		cleanup := p.sm.HandleAccept(p.conn)
		t.Cleanup(cleanup)
		cer := regressionCER(t, dictionary, 4)
		setWireIdentity(t, cer, avp.OriginHost, "peer.example")
		setWireIdentity(t, cer, avp.OriginRealm, "example")
		cer.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
		p.receive(t, cer)
		if answer := <-p.wire.writes; !testResultCode(answer, diam.Success) {
			t.Fatalf("admission CEA = %v", answer)
		}
	} else {
		client := &Client{Handler: p.sm, Dict: dictionary, Logger: p.logs.Logger(), RetransmitInterval: time.Hour}
		dialed := make(chan protocolClientDialResult, 1)
		go func() {
			c, err := client.dial(func(activity *watchdogActivity) (diam.Conn, error) {
				return client.server("", "synthetic", nil, activity).NewConn(p.wire)
			})
			dialed <- protocolClientDialResult{conn: c, err: err}
		}()
		p.receive(t, protocolClientCEA(<-p.wire.writes, diam.Success))
		result := <-dialed
		if result.err != nil {
			t.Fatal(result.err)
		}
		p.conn = result.conn
	}
	t.Cleanup(func() { p.conn.Close() })
	synctest.Wait()
	return p
}

func (p *rejectionConstructionPeer) receive(t *testing.T, message *diam.Message) {
	t.Helper()
	wire, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p.wire.reads <- finalDPARead{data: wire}
}

func TestClosingRejectionSkipsUnavailableAnswerGrammar(t *testing.T) {
	for _, role := range []string{"accepted", "client"} {
		for _, outcome := range []string{"answer", "deadline"} {
			t.Run(role+"/"+outcome, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p := newRejectionConstructionPeer(t, role)
					disconnected := make(chan error, 1)
					go func() { disconnected <- p.sm.Disconnect(p.conn, DisconnectBusy, time.Hour) }()
					dpr := <-p.wire.writes
					synctest.Wait()
					state := p.sm.acceptedCore(p.conn, nil, false)
					before := state.snapshot().Timer(protocol.ClosingTimer)
					request := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 23, 24, p.conn.Dictionary())
					request.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
					request.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
					request.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
					request.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
					request = decodeRejectionRequest(t, request, rejectionConstructionDictionary(t, false))
					if err := base.ValidateMessage(request); err != nil {
						t.Fatalf("DPR must satisfy unconditional base grammar: %v", err)
					}
					if _, err := base.BuildErrorAnswer(request, baseSettings(p.sm.cfg), diam.AVPUnsupported, []*diam.AVP{request.AVP[len(request.AVP)-1]}, false); err == nil || !strings.Contains(err.Error(), "command code 282: dictionary entry not found") {
						t.Fatalf("fixture must fail answer grammar lookup: %v", err)
					}
					p.sm.ServeDIAM(p.conn, request)
					synctest.Wait()
					event := <-p.events
					assertProtocolEvent(t, event, p.conn, request.Header, diam.ProtocolUnsupportedAVP, diam.AVPUnsupported, false, diam.ProtocolReplyNone, 0)
					after := state.snapshot()
					if p.conn.Closed() || after.Phase() != protocol.Closing || after.Timer(protocol.ClosingTimer) != before || len(p.wire.writes) != 0 {
						t.Fatalf("discard changed Closing: closed=%t timer=%+v writes=%d", p.conn.Closed(), after.Timer(protocol.ClosingTimer), len(p.wire.writes))
					}
					select {
					case err := <-disconnected:
						t.Fatalf("discard completed Disconnect: %v", err)
					default:
					}
					var want error
					if outcome == "answer" {
						p.receive(t, finalDPAnswer(dpr))
					} else {
						time.Sleep(time.Until(before.Deadline))
						want = ErrDisconnectTimeout
					}
					synctest.Wait()
					if err := <-disconnected; !errors.Is(err, want) || !p.conn.Closed() {
						t.Fatalf("Disconnect = %v, want %v; closed=%t", err, want, p.conn.Closed())
					}
				})
			})
		}
	}
}

func TestInvalidHeaderWarningAfterAnswerConstruction(t *testing.T) {
	for _, role := range []string{"accepted", "client"} {
		for _, failBuilder := range []bool{false, true} {
			name := "written"
			if failBuilder {
				name = "construction-failed"
			}
			t.Run(role+"/"+name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p := newRejectionConstructionPeer(t, role)
					start := len(p.logs.Records())
					request := regressionDWR(t)
					request.Header.CommandFlags |= diam.ProxiableFlag
					dictionary := p.conn.Dictionary()
					if failBuilder {
						dictionary = rejectionConstructionDictionary(t, true)
					}
					request = decodeRejectionRequest(t, request, dictionary)
					p.sm.ServeDIAM(p.conn, request)
					synctest.Wait()
					reply, code := diam.ProtocolReplyWritten, uint32(diam.InvalidHDRBits)
					if failBuilder {
						reply = diam.ProtocolReplyFailed
					}
					event := <-p.events
					assertProtocolEvent(t, event, p.conn, request.Header, diam.ProtocolInvalidHeader, code, failBuilder, reply, code)
					records := p.logs.Records()[start:]
					wantRecords := 1
					if failBuilder {
						wantRecords = 2
					}
					if len(records) != wantRecords || records[0].Level != slog.LevelWarn || records[0].Message != "sm: invalid message header" {
						t.Fatalf("header logs = %v", records)
					}
					value := logtest.Attr(records[0], "error").Any()
					if failBuilder {
						cause, ok := value.(*diam.ProtocolError)
						if !ok || cause.Kind() != diam.ProtocolInvalidHeader || cause.ResultCode() != code || cause.Error() != diam.NewProtocolError(diam.ProtocolInvalidHeader, code).Error() {
							t.Fatalf("header construction warning = %T %v", value, value)
						}
						if errors.Unwrap(cause) != diam.ProtocolInvalidHeader || errors.Unwrap(errors.Unwrap(cause)) != nil {
							t.Fatalf("header construction warning changed unwrap chain: %v", cause)
						}
					} else {
						cause, ok := value.(*diam.MessageError)
						want := base.ValidateHeader(request)
						if !ok || cause.Error() != want.Error() || errors.Unwrap(cause).Error() != errors.Unwrap(want).Error() {
							t.Fatalf("written header warning = %T %v, want %v", value, value, want)
						}
					}
				})
			})
		}
	}
}
