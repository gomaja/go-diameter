package sm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 §§5.3, 5.6: removing external claims in a repeated-CER hook
// restores admission gating without turning that already classified CER into
// another capabilities exchange.
func TestAdmittedRepeatedCERHookRevocationWire(t *testing.T) {
	for _, shape := range []string{"CEA", "both"} {
		t.Run(shape, func(t *testing.T) {
			d := newSMTestDictionary(creditcontrol.Dictionary())
			cfg := testMessageErrorSettings(d)
			cfg.HostIPAddresses = []datatype.Address{localhostAddress}
			cfg.ValidateRequests = false
			var cerHooks, ceaHooks, handshakes atomic.Int32
			outcomes := make(chan string, 4)
			cfg.OnCER = func(c diam.Conn, _ *diam.Message) {
				cerHooks.Add(1)
				replaceAdmission(c, "absent")
			}
			cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaHooks.Add(1); outcomes <- "CEA" }
			cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
			cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				outcomes <- fmt.Sprintf("%s/%d", e.Err.Kind(), e.Err.ResultCode())
			}
			sm := mustNewStateMachine(t, cfg, d)
			sm.HandleIdx(diam.CommandIndex{AppID: 4, Code: 0xeeff, Request: true}, diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
				if _, err := m.Answer(diam.Success).WriteTo(c); err != nil {
					t.Error(err)
				}
			}))
			opened := make(chan diam.Conn, 1)
			srv := diamtest.NewUnstartedServer(diam.HandlerFunc(sm.ServeDIAM), d)
			srv.Config.OnNewConnection = func(c diam.Conn) { replaceAdmission(c, shape); opened <- c }
			srv.Start()
			defer srv.Close()
			peer, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var c diam.Conn
			select {
			case c = <-opened:
			case <-time.After(15 * time.Second):
				t.Fatal("connection was not opened")
			}
			cer := regressionCER(t, d, 1001)
			if _, err := cer.WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			select {
			case outcome := <-outcomes:
				if outcome == "CEA" {
					answer, readErr := diam.ReadMessage(peer, d)
					t.Fatalf("repeated CER produced an admission CEA on the wire: message=%v error=%v", answer, readErr)
				}
				if outcome != fmt.Sprintf("%s/0", diam.ProtocolUnexpectedMessage) {
					t.Fatalf("repeat disposition=%s", outcome)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("repeated CER disposition was not published")
			}
			// Restore claims for a later application frame. Its response is a positive
			// wire fence: any CEA for the repeated CER would arrive before this answer.
			replaceAdmission(c, shape)
			fence := diam.NewMessage(0xeeff, diam.RequestFlag, 4, 31, 32, d)
			if _, err := fence.WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			answer, err := diam.ReadMessage(peer, d)
			if err != nil || answer.Header.CommandCode != fence.Header.CommandCode || answer.Header.HopByHopID != fence.Header.HopByHopID || answer.Header.EndToEndID != fence.Header.EndToEndID || !testResultCode(answer, diam.Success) {
				t.Fatalf("application wire fence=%v error=%v", answer, err)
			}
			if cerHooks.Load() != 1 || ceaHooks.Load() != 0 || handshakes.Load() != 0 {
				t.Fatalf("repeat callbacks CER/CEA/handshake=%d/%d/%d", cerHooks.Load(), ceaHooks.Load(), handshakes.Load())
			}
			if state := sm.acceptedCore(c, nil, false); state == nil || !state.passiveResponder() {
				t.Fatal("repeat transferred external admission ownership")
			}
		})
	}
}

func TestAdmittedCERHeaderRejectionWire(t *testing.T) {
	for _, admission := range []string{"CER", "CEA", "both"} {
		for _, hooks := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Hooks=%t", admission, hooks), func(t *testing.T) {
				var baselineLogs []string
				var baselineRan bool
				for _, shape := range []string{"ApplicationID", "Proxiable", "Error", "Repeated"} {
					t.Run(shape, func(t *testing.T) {
						d := newSMTestDictionary(creditcontrol.Dictionary())
						cfg := testMessageErrorSettings(d)
						cfg.HostIPAddresses = []datatype.Address{localhostAddress}
						var cerCalls, ceaCalls, handshakes atomic.Int32
						if hooks {
							cfg.OnCER = func(diam.Conn, *diam.Message) { cerCalls.Add(1) }
							cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaCalls.Add(1) }
						}
						cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
						events := make(chan diam.ProtocolErrorEvent, 8)
						cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
						sm := mustNewStateMachine(t, cfg, d)
						logs := logtest.New()
						opened := make(chan diam.Conn, 1)
						srv := diamtest.NewUnstartedServer(contextAdmissionMessageErrors{sm}, d)
						srv.Config.Logger = logs.Logger()
						srv.Config.OnNewConnection = func(c diam.Conn) { replaceAdmission(c, admission); opened <- c }
						srv.Start()
						defer srv.Close()
						wire, err := net.Dial("tcp", srv.Addr)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = wire.Close() }()
						if err := wire.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
							t.Fatal(err)
						}
						var conn diam.Conn
						select {
						case conn = <-opened:
						case <-time.After(10 * time.Second):
							t.Fatal("connection did not open")
						}
						p := &protocolWire{sm: sm, peer: wire, conn: conn, events: events, logs: logs}
						cer := regressionCER(t, d, 1001)
						switch shape {
						case "ApplicationID":
							cer.Header.ApplicationID = 1001
						case "Proxiable":
							cer.Header.CommandFlags |= diam.ProxiableFlag
						case "Error":
							cer.Header.CommandFlags |= diam.ErrorFlag
						}
						header := p.send(t, cer)
						if shape == "Repeated" {
							if admission != "CER" {
								event := protocolEvent(t, events)
								assertProtocolEvent(t, event, conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
							}
							p.usable(t)
							wantCER := int32(0)
							if hooks && admission != "CER" {
								wantCER = 1
							}
							if cerCalls.Load() != wantCER || ceaCalls.Load() != 0 || handshakes.Load() != 0 {
								t.Fatalf("repeat callbacks CER/CEA/handshake=%d/%d/%d; want %d/0/0", cerCalls.Load(), ceaCalls.Load(), handshakes.Load(), wantCER)
							}
							select {
							case event := <-events:
								t.Fatalf("additional protocol event: %+v", event)
							default:
							}
							return
						}
						answer, err := diam.ReadMessage(wire, d)
						if err != nil {
							t.Fatal(err)
						}
						wantFlags := uint8(diam.ErrorFlag) | header.CommandFlags&diam.ProxiableFlag
						if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags != wantFlags || answer.Header.ApplicationID != 0 ||
							answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID || !testResultCode(answer, diam.InvalidHDRBits) {
							t.Fatalf("invalid CER answer=%v; want 3008 flags=%02x app=0 IDs=%08x/%08x", answer, wantFlags, header.HopByHopID, header.EndToEndID)
						}
						for code, want := range map[uint32]datatype.DiameterIdentity{avp.OriginHost: cfg.OriginHost, avp.OriginRealm: cfg.OriginRealm} {
							field, err := answer.FindAVP(code, 0)
							if err != nil || field.Data != want {
								t.Fatalf("origin AVP %d=%v %v; want %q", code, field, err, want)
							}
						}
						event := protocolEvent(t, events)
						assertProtocolEvent(t, event, conn, &header, diam.ProtocolInvalidHeader, diam.InvalidHDRBits, true, diam.ProtocolReplyWritten, diam.InvalidHDRBits)
						var b [1]byte
						if n, err := wire.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
							t.Fatalf("closure=%d,%v; want EOF", n, err)
						}
						wantCEA := int32(0)
						if hooks {
							wantCEA = 1
						}
						if cerCalls.Load() != 0 || ceaCalls.Load() != wantCEA || handshakes.Load() != 0 {
							t.Fatalf("invalid CER callbacks CER/CEA/handshake=%d/%d/%d; want 0/%d/0", cerCalls.Load(), ceaCalls.Load(), handshakes.Load(), wantCEA)
						}
						var messages []string
						for _, record := range logs.Records() {
							if record.Level >= slog.LevelWarn {
								messages = append(messages, fmt.Sprintf("%s/%s", record.Level, record.Message))
							}
						}
						if shape == "ApplicationID" {
							baselineLogs, baselineRan = messages, true
						} else if baselineRan && !reflect.DeepEqual(messages, baselineLogs) {
							t.Fatalf("rejection logs=%v; ApplicationID control=%v", messages, baselineLogs)
						}
						select {
						case extra := <-events:
							t.Fatalf("additional protocol event: %+v", extra)
						default:
						}
					})
				}
			})
		}
	}
}
