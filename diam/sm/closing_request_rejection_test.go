package sm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

type closingRejectionContextKey struct{}

// A malformed simultaneous DPR cannot replace the caller's outstanding local
// disconnect deadline or select another reply. Retaining typed validation
// evidence internally preserves the public diagnostic's ProtocolError type.
func TestClosingRequestRejectionPreservesDisconnectDeadline(t *testing.T) {
	for _, role := range []string{"accepted", "client"} {
		for _, condition := range []string{"missing-origin", "mandatory-avp"} {
			t.Run(role+"/"+condition, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sm, c, logs, events, cleanup := newClosingRejectionPeer(t, role)
					defer cleanup()
					state := sm.acceptedCore(c, nil, false)
					if state == nil {
						t.Fatal("admitted connection has no protocol owner")
					}
					disconnected := make(chan error, 1)
					go func() { disconnected <- sm.Disconnect(c, DisconnectBusy, time.Hour) }()
					synctest.Wait()
					defer func() {
						c.Close()
						synctest.Wait()
						if err := <-disconnected; !errors.Is(err, ErrDisconnectClosed) {
							t.Errorf("Disconnect = %v, want ErrDisconnectClosed", err)
						}
					}()
					if state.snapshot().Phase() != protocol.Closing {
						t.Fatal("Disconnect did not enter Closing")
					}
					if dpr := closingRejectionWrite(t, c); dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
						t.Fatalf("disconnect writer selected %v", dpr)
					}
					before := state.snapshot().Timer(protocol.ClosingTimer)
					beforeLogs := len(logs.Records())
					time.Sleep(time.Second)
					request := regressionDWR(t)
					request.Header.CommandCode = diam.DisconnectPeer
					request.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Unsigned32(0)))
					kind, code, text := diam.ProtocolInvalidRequest, uint32(diam.MissingAVP), "sm: invalid request"
					if condition == "missing-origin" {
						var kept []*diam.AVP
						for _, a := range request.AVP {
							if a.Code != avp.OriginHost {
								kept = append(kept, a)
							}
						}
						request.AVP = kept
					} else {
						request.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown([]byte{1, 2, 3, 4})))
						kind, code, text = diam.ProtocolUnsupportedAVP, diam.AVPUnsupported, "sm: unsupported mandatory AVP"
					}
					wire, err := request.Serialize()
					if err != nil {
						t.Fatal(err)
					}
					request, err = diam.ReadMessage(bytes.NewReader(wire), c.Dictionary())
					if err != nil {
						t.Fatal(err)
					}
					requestContext := context.WithValue(context.Background(), closingRejectionContextKey{}, "request")
					request.SetContext(requestContext)
					sm.ServeDIAM(c, request)
					synctest.Wait()
					after := state.snapshot()
					timer := after.Timer(protocol.ClosingTimer)
					if c.Closed() || after.Phase() != protocol.Closing || len(c.writes) != 0 {
						t.Fatalf("rejected DPR changed Closing: closed=%t phase=%v writes=%d", c.Closed(), after.Phase(), len(c.writes))
					}
					if before.Token == 0 || timer.Token != before.Token || !timer.Deadline.Equal(before.Deadline) || time.Until(timer.Deadline) != time.Hour-time.Second {
						t.Fatalf("rejected DPR changed the disconnect deadline: before=%+v after=%+v", before, timer)
					}
					if len(events) != 1 {
						t.Fatalf("protocol notifications = %d, want one", len(events))
					}
					event := <-events
					assertProtocolEvent(t, event, c, request.Header, kind, code, false, diam.ProtocolReplyNone, 0)
					records := logs.Records()[beforeLogs:]
					if len(records) != 1 {
						t.Fatalf("rejection logs = %v, want one", records)
					}
					record := records[0]
					if record.Level != slog.LevelWarn || record.Message != text || logs.Contexts()[beforeLogs] != requestContext {
						t.Fatalf("rejection changed log level, text or context: %v", record)
					}
					diagnostic, ok := logtest.Attr(record, "error").Any().(*diam.ProtocolError)
					if !ok || diagnostic.Kind() != kind || diagnostic.ResultCode() != code || diagnostic.Error() != diam.NewProtocolError(kind, code).Error() {
						t.Fatalf("rejection changed diagnostic type/value: %T %v", logtest.Attr(record, "error").Any(), logtest.Attr(record, "error").Any())
					}
					if cause, ok := errors.Unwrap(diagnostic).(diam.ProtocolErrorKind); !ok || cause != kind {
						t.Fatalf("diagnostic cause = %T %v", errors.Unwrap(diagnostic), errors.Unwrap(diagnostic))
					}
				})
			})
		}
	}
}

func newClosingRejectionPeer(t *testing.T, role string) (*StateMachine, *errorDispositionConn, *logtest.Recorder, chan diam.ProtocolErrorEvent, func()) {
	t.Helper()
	logs := logtest.New()
	c := &errorDispositionConn{handshakeConn: newHandshakeConn(), logger: logs.Logger(), done: make(chan struct{})}
	cfg := testMessageErrorSettings(c.Dictionary())
	cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
	cfg.ValidateRequests, cfg.RejectUnknownMandatoryAVPs = true, true
	cfg.EnableWatchdog, cfg.WatchdogInterval = true, time.Hour
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	events := make(chan diam.ProtocolErrorEvent, 8)
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	sm := mustNewStateMachine(t, cfg, c.Dictionary())
	var acceptCleanup func()
	var cancel context.CancelFunc
	if role == "accepted" {
		acceptCleanup = sm.HandleAccept(c)
		sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), 1001))
		if cea := closingRejectionWrite(t, c); !testResultCode(cea, diam.Success) {
			t.Fatalf("initial CEA = %v", cea)
		}
	} else {
		cli := &Client{Handler: sm, Dict: c.Dictionary(), EnableWatchdog: true, WatchdogInterval: time.Hour, watchdogTiming: &watchdogTiming{floor: time.Millisecond}, RetransmitInterval: time.Hour}
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := cli.dialContext(ctx, func(*watchdogActivity) (diam.Conn, error) { return c, nil })
			result <- err
		}()
		synctest.Wait()
		cer := closingRejectionWrite(t, c)
		answer := protocolClientCEA(cer, diam.Success)
		answer.AddAVP(diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001)))
		setWireIdentity(t, answer, avp.OriginHost, string(clientSettings.OriginHost))
		setWireIdentity(t, answer, avp.OriginRealm, string(clientSettings.OriginRealm))
		sm.ServeDIAM(c, answer)
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("Client dial = %v", err)
		}
	}
	synctest.Wait()
	return sm, c, logs, events, func() {
		c.Close()
		if acceptCleanup != nil {
			acceptCleanup()
		}
		if cancel != nil {
			cancel()
		}
		synctest.Wait()
	}
}

func closingRejectionWrite(t *testing.T, c *errorDispositionConn) *diam.Message {
	t.Helper()
	select {
	case wire := <-c.writes:
		m, err := diam.ReadMessage(bytes.NewReader(wire), c.Dictionary())
		if err != nil {
			t.Fatal(err)
		}
		return m
	default:
		t.Fatal("required adapter write missing")
		return nil
	}
}
