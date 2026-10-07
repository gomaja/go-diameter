package sm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestHandshakeFailureHasOneDecisionRecord(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%t", malformed), func(t *testing.T) {
			logs := logtest.New()
			c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			cli := &Client{Handler: sm, RetransmitInterval: time.Second}
			activity := newWatchdogActivity()
			activity.capabilities = cli.capabilitySettings(nil)
			h := activityHandler{StateMachine: sm, activity: activity}
			done := make(chan error, 1)
			go func() { _, err := cli.handshake(c, activity); done <- err }()
			select {
			case <-c.writes:
			case <-time.After(time.Second):
				t.Fatal("CER not written")
			}
			if malformed {
				if err := h.HandleMessageError(c, regressionDWR(t), &diam.MessageError{ResultCode: diam.InvalidAVPLength}); err != nil {
					t.Fatal(err)
				}
			} else {
				h.ServeDIAM(c, regressionDWR(t))
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("handshake accepted non-CEA")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake did not fail")
			}
			records := logs.Records()
			if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: Wait-I-CEA rejected message; closing connection" {
				t.Fatalf("decision records=%v, want one accurate Wait-I-CEA Warn", records)
			}
		})
	}
}

func TestCEARejectionRecordsBeforePublishingFailure(t *testing.T) {
	logs := logtest.New()
	entered, release := make(chan struct{}), make(chan struct{})
	c := loggerHandshakeConn{newHandshakeConn(), slog.New(blockingSMLog{logs, entered, release})}
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	activity := newWatchdogActivity()
	done := make(chan struct{})
	go func() {
		handleCEA(sm, activity)(c, diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 1, 2, dict.Default))
		close(done)
	}()
	select {
	case <-entered:
	case <-done:
		t.Fatal("CEA failure published without decision record")
	case <-time.After(time.Second):
		t.Fatal("CEA validation stalled")
	}
	select {
	case err := <-activity.ceac:
		activity.ceac <- err
		t.Error("CEA failure published before decision record completed")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CEA handler stalled")
	}
	if err := <-activity.ceac; err == nil {
		t.Fatal("invalid CEA accepted")
	}
	records := logs.Records()
	if len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: CEA rejected; closing connection" {
		t.Fatalf("CEA records=%v", records)
	}
}

func TestEmptyStateMachineRegistrationPanicPrefix(t *testing.T) {
	for _, api := range []string{"Handle", "HandleFunc"} {
		t.Run(api, func(t *testing.T) {
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			defer func() {
				if got := fmt.Sprint(recover()); !strings.HasPrefix(got, "sm:") {
					t.Fatalf("panic=%q, want sm: prefix", got)
				}
			}()
			noop := diam.HandlerFunc(func(diam.Conn, *diam.Message) {})
			if api == "Handle" {
				sm.Handle("", noop)
			} else {
				sm.HandleFunc("", noop)
			}
		})
	}
}

func TestErrorAnswerFailureOwnedByStateMachine(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(fmt.Sprintf("unsupported=%t", unsupported), func(t *testing.T) {
			logs := logtest.New()
			c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
			c.writeErr = errors.New("answer write failed")
			c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{}))
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			m := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 1, 2, dict.Default)
			c.afterClose = func() {
				records := logs.Records()
				if len(records) != 1 || records[0].Level != slog.LevelError {
					t.Errorf("close before sole write failure record: %v", records)
				}
			}
			if unsupported {
				sm.ServeDIAM(c, m)
			} else if err := sm.HandleMessageError(c, m, &diam.MessageError{ResultCode: diam.CommandUnsupported}); err != nil {
				t.Errorf("owned write failure returned to server: %v", err)
			}
			if !c.closed.Load() {
				t.Error("write failure left connection open")
			}
			records := logs.Records()
			if len(records) != 1 || records[0].Level != slog.LevelError || records[0].Message != "sm: error answer failed" || !errors.Is(logError(records[0]), c.writeErr) {
				t.Fatalf("write failure records=%v", records)
			}
		})
	}
}

type failedAnswerListener struct{ net.Listener }
type failedAnswerConn struct{ net.Conn }

func (c failedAnswerConn) Write([]byte) (int, error) {
	return 0, errors.New("injected answer write failure")
}
func (l failedAnswerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return failedAnswerConn{c}, nil
}

func TestMalformedAnswerWriteFailureLogsOnce(t *testing.T) {
	logs := logtest.New()
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	srv := diamtest.NewUnstartedServer(sm, dict.Default)
	srv.Listener = failedAnswerListener{srv.Listener}
	srv.Config.Logger = logs.Logger()
	srv.Start()
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err = c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, c, testSMErrorMessage(t, diam.RequestFlag, []byte{0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff}))
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("reply=%x err=%v, want EOF without answer", b[:n], err)
	}
	srv.Close()
	records := logs.Records()
	if len(records) != 2 || records[0].Level != slog.LevelWarn || records[0].Message != "diam: malformed message" || records[1].Level != slog.LevelError || records[1].Message != "sm: error answer failed" {
		t.Fatalf("malformed/write failure records=%v, want initial Warn and one writer Error", records)
	}
}

func admissionWiring(name string, sm *StateMachine) diam.Handler {
	switch name {
	case "opaque":
		return diam.HandlerFunc(sm.ServeDIAM)
	case "mux":
		mux := diam.NewServeMux()
		mux.Handle("ALL", sm)
		return mux
	default:
		return sm
	}
}

// RFC 6733 §5.6.1 rejects non-CER traffic even when optional HandleAccept
// discovery cannot reach the state machine through the server's handler.
func TestPreHandshakeMessagesRejectedInEveryWiring(t *testing.T) {
	for _, wiring := range []string{"direct", "opaque", "mux"} {
		for _, kind := range []string{"DWR", "application request", "application answer", "CEA"} {
			t.Run(wiring+"/"+kind, func(t *testing.T) {
				logs := logtest.New()
				sm := mustNewStateMachine(t, testMessageErrorSettings())
				sm.HandleFunc("ALL", func(diam.Conn, *diam.Message) { t.Error("pre-handshake application handler invoked") })
				m := regressionDWR(t)
				switch kind {
				case "application request":
					m = diam.NewMessage(diam.CreditControl, diam.RequestFlag, 4, 1, 2, dict.Default)
				case "application answer":
					m = diam.NewMessage(diam.CreditControl, 0, 4, 1, 2, dict.Default)
				case "CEA":
					m = diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 1, 2, dict.Default)
				}
				// Inspect synchronously at Close to prove that the decision precedes it.
				c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
				c.afterClose = func() {
					records := logs.Records()
					if len(records) != 1 || records[0].Level != slog.LevelWarn {
						t.Errorf("close before one Warn: %v", records)
					}
				}
				if wiring == "direct" {
					cleanup := sm.HandleAccept(c)
					defer cleanup()
				}
				admissionWiring(wiring, sm).ServeDIAM(c, m)
				if !c.closed.Load() {
					t.Error("pre-handshake traffic did not close connection")
				}
				if c.writeSeq.Load() != 0 {
					t.Errorf("pre-handshake traffic received %d answers", c.writeSeq.Load())
				}
				records := logs.Records()
				if len(records) != 1 || records[0].Message != "sm: message before CER; closing connection" {
					t.Fatalf("decision records=%v", records)
				}
			})
		}
	}
}

func TestHandshakeAllowsMessagesInEveryWiring(t *testing.T) {
	for _, wiring := range []string{"direct", "opaque", "mux"} {
		t.Run(wiring, func(t *testing.T) {
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			calls := 0
			sm.HandleFunc("ALL", func(diam.Conn, *diam.Message) { calls++ })
			c := newHandshakeConn()
			if wiring == "direct" {
				cleanup := sm.HandleAccept(c)
				defer cleanup()
			}
			h := admissionWiring(wiring, sm)
			h.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
			if !admittedPeer(c) {
				t.Fatal("valid CER did not admit peer")
			}
			h.ServeDIAM(c, regressionDWR(t))
			h.ServeDIAM(c, diam.NewMessage(diam.CreditControl, diam.RequestFlag, 4, 1, 2, dict.Default))
			h.ServeDIAM(c, diam.NewMessage(diam.CreditControl, 0, 4, 1, 2, dict.Default))
			if c.closed.Load() || c.writeSeq.Load() != 2 || calls != 2 {
				t.Fatalf("admitted peer: closed=%t writes=%d application calls=%d", c.closed.Load(), c.writeSeq.Load(), calls)
			}
		})
	}
}

func TestHandshakeHandlerGuardLogsBeforeClose(t *testing.T) {
	logs := logtest.New()
	c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
	c.afterClose = func() {
		if len(logs.Records()) != 1 {
			t.Error("close before handshake guard record")
		}
	}
	handshakeOK(func(diam.Conn, *diam.Message) { t.Error("handler called before handshake") }).ServeDIAM(c, regressionDWR(t))
	records := logs.Records()
	if !c.closed.Load() || len(records) != 1 || records[0].Level != slog.LevelWarn {
		t.Fatalf("guard closed=%t records=%v", c.closed.Load(), records)
	}
}

func TestDirectErrorAnswerPreservesWriteFailure(t *testing.T) {
	logs := logtest.New()
	c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
	c.writeErr = errors.New("answer write failed")
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	if err := sm.writeErrorAnswer(c, regressionDWR(t), diam.CommandUnsupported, nil, true); !errors.Is(err, c.writeErr) {
		t.Fatalf("writeErrorAnswer error=%v", err)
	}
	if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelError {
		t.Fatalf("writer records=%v", records)
	}
}

func TestPreHandshakeRejectionTCPInEveryWiring(t *testing.T) {
	for _, wiring := range []string{"direct", "opaque", "mux"} {
		for _, request := range []bool{false, true} {
			for _, command := range []uint32{diam.DeviceWatchdog, diam.CreditControl} {
				t.Run(fmt.Sprintf("%s/request=%t/command=%d", wiring, request, command), func(t *testing.T) {
					logs := logtest.New()
					sm := mustNewStateMachine(t, testMessageErrorSettings())
					sm.HandleFunc("ALL", func(diam.Conn, *diam.Message) { t.Error("pre-handshake handler invoked") })
					srv := diamtest.NewUnstartedServer(admissionWiring(wiring, sm), dict.Default)
					srv.Config.Logger = logs.Logger()
					srv.Start()
					defer srv.Close()
					c, err := net.Dial("tcp", srv.Addr)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = c.Close() }()
					if err = c.SetDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					flags, app := uint8(0), uint32(0)
					if request {
						flags = diam.RequestFlag
					}
					if command == diam.CreditControl {
						app = 4
					}
					if _, err := diam.NewMessage(command, flags, app, 1, 2, dict.Default).WriteTo(c); err != nil {
						t.Fatal(err)
					}
					var b [1]byte
					if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Fatalf("pre-handshake reply=%x err=%v, want EOF without answer", b[:n], err)
					}
					srv.Close()
					if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: message before CER; closing connection" {
						t.Fatalf("pre-handshake records=%v", records)
					}
				})
			}
		}
	}
}

func TestUnhandledPreHandshakeMessagesRejected(t *testing.T) {
	for _, wiring := range []string{"direct", "opaque", "mux"} {
		for _, request := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/request=%t", wiring, request), func(t *testing.T) {
				logs := logtest.New()
				sm := mustNewStateMachine(t, testMessageErrorSettings())
				c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
				if wiring == "direct" {
					cleanup := sm.HandleAccept(c)
					defer cleanup()
				}
				flags := uint8(0)
				if request {
					flags = diam.RequestFlag
				}
				admissionWiring(wiring, sm).ServeDIAM(c, diam.NewMessage(0xfedc, flags, 0, 1, 2, dict.Default))
				if !c.closed.Load() || c.writeSeq.Load() != 0 {
					t.Errorf("unhandled pre-handshake closed=%t writes=%d", c.closed.Load(), c.writeSeq.Load())
				}
				if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn || records[0].Message != "sm: message before CER; closing connection" {
					t.Fatalf("records=%v", records)
				}
			})
		}
	}
}

func TestIndexedWatchdogRequiresHandshake(t *testing.T) {
	logs := logtest.New()
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	c := loggerHandshakeConn{newHandshakeConn(), logs.Logger()}
	m := regressionDWR(t)
	handler, ok := sm.mux.Handler(m)
	if !ok {
		t.Fatal("missing base DWR handler")
	}
	handler.ServeDIAM(c, m)
	if !c.closed.Load() || c.writeSeq.Load() != 0 {
		t.Errorf("indexed DWR closed=%t answers=%d", c.closed.Load(), c.writeSeq.Load())
	}
	if records := logs.Records(); len(records) != 1 || records[0].Level != slog.LevelWarn {
		t.Fatalf("indexed DWR records=%v", records)
	}
}
