package peer

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type errorAnswerBuildWire struct {
	m      *Manager
	c      net.Conn
	s      *session
	a      *actor
	events chan diam.ProtocolErrorEvent
	peers  chan PeerEvent
}

func newErrorAnswerBuildWire(t *testing.T, open bool) *errorAnswerBuildWire {
	t.Helper()
	p := &errorAnswerBuildWire{events: make(chan diam.ProtocolErrorEvent, 16), peers: make(chan PeerEvent, 32)}
	settings := testSettings("local.example.net")
	settings.ValidateRequests = true
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	var err error
	p.m, err = New(Config{Settings: settings, Clock: &fakeClock{}, OnPeerEvent: func(e PeerEvent) { p.peers <- e }})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true}); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan diam.Conn, 1)
	srv := &diam.Server{Dict: p.m.dictionary(), MaxConcurrentHandlers: 8, OnNewConnection: func(c diam.Conn) { accepted <- c }}
	if err = p.m.BindServer(srv); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		if p.c != nil {
			_ = p.c.Close()
		}
		closeManager(t, p.m, srv)
	})
	p.c, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	native := renewalScriptReceive(t, accepted, "native TCP acceptance")
	p.s = p.m.getSession(native)
	if p.s == nil {
		t.Fatal("accepted TCP session not registered")
	}
	if open {
		write(t, p.c, capabilitiesExchangeRequest(t))
		if code(t, read(t, p.c)) != diam.Success {
			t.Fatal("initial CER rejected")
		}
		awaitState(t, p.m, ROpen)
		p.a, _ = p.s.binding()
		p.a.commit(event{}, newProtocolDelivery())
	}
	return p
}

// The observer queue barrier completes earlier nonnil reasons without assuming
// when native EOF cleanup will enqueue its separate transport-closed notice.
func (p *errorAnswerBuildWire) reasons(t *testing.T) []PeerEvent {
	t.Helper()
	marker := errors.New("observer completion")
	p.m.notify(PeerEvent{Reason: marker})
	var events []PeerEvent
	for {
		event := renewalScriptReceive(t, p.peers, "peer observer completion")
		if event.Reason == marker {
			return events
		}
		if event.Reason != nil {
			events = append(events, event)
		}
	}
}

// The session and its handshake use real TCP. The empty request dictionary is
// supplied through public callbacks: dictionary pointers do not travel on wire.
// It makes the automatic answer builder fail without changing Manager settings.
func TestManagerErrorAnswerBuildFailurePreservesDiagnosticsTCP(t *testing.T) {
	cases := []struct {
		name           string
		open, callback bool
		command        uint32
	}{
		{"pre-CER-callback", false, true, diam.CapabilitiesExchange},
		{"pre-CER-decoded-missing-AVP", false, false, diam.CapabilitiesExchange},
		{"Open-CER-callback", true, true, diam.CapabilitiesExchange},
		{"Open-decoded-malformed-DWR", true, false, diam.DeviceWatchdog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := publicErrorLog(t)
			p := newErrorAnswerBuildWire(t, tc.open)
			setup := p.reasons(t)
			if tc.open {
				if len(setup) != 1 || setup[0].Peer.State != ROpen || setup[0].Reason.Error() != "peer: initial connection established" {
					t.Fatalf("initial connection reasons=%+v", setup)
				}
			} else if len(setup) != 0 {
				t.Fatalf("unexpected setup reasons=%+v", setup)
			}
			start := len(records.Records())
			empty, err := dict.NewParser()
			if err != nil {
				t.Fatal(err)
			}
			message := diam.NewMessage(tc.command, diam.RequestFlag, 0, 11, 12, empty)
			kind, result := diam.ProtocolInvalidRequest, uint32(diam.MissingAVP)
			failureLog := "peer: request rejection answer failed"
			if tc.callback {
				kind, result = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
				failureLog = "peer: error answer failed; closing connection"
				err = p.m.HandleMessageError(p.s.c, message, &diam.MessageError{ResultCode: result, Fatal: true, Err: errors.New("callback decode failure")})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				p.m.ServeDIAM(p.s.c, message)
			}
			notice := protocolErrorReceive(t, p.events)
			protocolErrorCheck(t, notice, p.s.c, *message.Header, kind, result, true, diam.ProtocolReplyFailed, result)
			correlationEOF(t, p.c)
			if p.a != nil {
				p.a.commit(event{}, newProtocolDelivery())
			}
			grammarText := "diameter message error 5005: Diameter validation failed (5005): required AVP missing"
			builderText := fmt.Sprintf("cannot form valid Diameter error answer: Diameter validation failed (3001): application 0: command code %d: dictionary entry not found", tc.command)
			type diagnostic struct {
				level                    slog.Level
				message, errorType, text string
			}
			expected := []diagnostic{{slog.LevelError, failureLog, "*fmt.wrapError", builderText}}
			if !tc.callback {
				expected = append([]diagnostic{{slog.LevelWarn, "peer: protocol error", "*diam.MessageError", grammarText}}, expected...)
			}
			logs := records.Records()[start:]
			if len(logs) != len(expected) {
				t.Fatalf("logs=%+v; want %d ordered records", logs, len(expected))
			}
			host := ""
			if tc.open {
				host = "known.example.net"
			}
			for i, want := range expected {
				record := logs[i]
				cause := logtest.Attr(record, "error").Any()
				if record.Level != want.level || record.Message != want.message || fmt.Sprintf("%T", cause) != want.errorType || fmt.Sprint(cause) != want.text || logtest.Attr(record, "peer_host").String() != host || logtest.Attr(record, "message.command_code").Uint64() != uint64(tc.command) {
					t.Fatalf("log %d: level=%s message=%q error=%T(%v) host=%v command=%v", i, record.Level, record.Message, cause, cause, logtest.Attr(record, "peer_host"), logtest.Attr(record, "message.command_code"))
				}
			}
			peers := p.reasons(t)
			if !tc.open {
				if len(peers) != 0 {
					t.Fatalf("unbound failure notified peer=%+v", peers)
				}
			} else {
				if len(peers) < len(expected) {
					t.Fatalf("peer reasons=%+v; missing ordered diagnostics", peers)
				}
				for i, want := range expected {
					got := peers[i]
					if got.Peer.State != ROpen || fmt.Sprintf("%T", got.Reason) != want.errorType || got.Reason.Error() != want.text {
						t.Fatalf("peer reason %d: state=%s reason=%T(%v)", i, got.Peer.State, got.Reason, got.Reason)
					}
				}
				for _, got := range peers[len(expected):] {
					if got.Peer.State != Closed || fmt.Sprintf("%T", got.Reason) != "*errors.errorString" || got.Reason.Error() != "peer: responder transport closed" {
						t.Fatalf("unexpected later peer reason=%+v", got)
					}
				}
			}
			if !p.s.c.Closed() {
				t.Fatal("answer build failure retained native transport")
			}
			select {
			case extra := <-p.events:
				t.Fatalf("duplicate protocol report=%+v", extra)
			default:
			}
		})
	}
}
