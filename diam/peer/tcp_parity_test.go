package peer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type parityFrontend struct {
	name               string
	manager, initiator bool
}

var parityFrontends = []parityFrontend{
	{name: "StateMachineAccepted"},
	{name: "Client", initiator: true},
	{name: "ManagerAccepted", manager: true},
	{name: "ManagerDialed", manager: true, initiator: true},
}

type parityTCP struct {
	frontend     parityFrontend
	wire         net.Conn
	dict         *dict.Parser
	events       chan diam.ProtocolErrorEvent
	ready        chan struct{}
	conn         diam.Conn
	done         <-chan error
	close        func() <-chan error
	send         func() <-chan parityApplicationResult
	handler      diam.MessageErrorHandler
	closeCause   func(uint32) <-chan error
	logs         *logtest.Recorder
	watchdog     chan sm.WatchdogEvent
	manager      *peer.Manager
	completedCEA diam.Header
	peers        chan peer.PeerEvent
}

type parityApplicationResult struct {
	answer *diam.Message
	err    error
}

func parityAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("connection did not reach the required protocol boundary")
		var zero T
		return zero
	}
}

// All frontends use the same capabilities, dictionary, validation and watchdog
// policy. Only the public construction/admission paths differ. Long protocol
// timers keep completion dependent on messages and callbacks, not elapsed time.
func parityStart(t *testing.T, frontend parityFrontend, handshake bool, application ...bool) *parityTCP {
	return parityStartConfigured(t, frontend, handshake, paritySettings{application: len(application) != 0 && application[0]})
}

type paritySettings struct {
	application bool
	probe       bool
	clock       *parityClock
	interval    time.Duration
	writeGate   *parityReplyGate
	onCEA       diam.HandlerFunc
	onCER       diam.HandlerFunc
}

func parityStartConfigured(t *testing.T, frontend parityFrontend, handshake bool, options paritySettings) *parityTCP {
	t.Helper()
	h := &parityTCP{frontend: frontend, dict: contractDict(t), events: make(chan diam.ProtocolErrorEvent, 64), ready: make(chan struct{})}
	h.logs, h.watchdog, h.peers = logtest.New(), make(chan sm.WatchdogEvent, 32), make(chan peer.PeerEvent, 64)
	interval := time.Hour
	if options.probe {
		interval = 6 * time.Second
	}
	if options.interval != 0 {
		interval = options.interval
	}
	settings := contractSettings(h.dict, true, true)
	settings.DPRCloseTimeout = time.Hour
	settings.HandshakeTimeout = time.Hour
	settings.OnProtocolError = func(event diam.ProtocolErrorEvent) { h.events <- event }
	settings.OnCEA = options.onCEA
	settings.OnCER = options.onCER
	logger := h.logs.Logger()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var ready sync.Once
	var server *diam.Server
	native := make(chan diam.Conn, 1)
	if frontend.manager {
		config := peer.Config{
			Settings: settings, Logger: logger,
			Timers: peer.Timers{TwInit: interval, CER: time.Hour, Closing: time.Hour},
			OnPeerEvent: func(event peer.PeerEvent) {
				h.peers <- event
				if event.Peer.Eligible {
					ready.Do(func() { close(h.ready) })
				}
			},
		}
		if options.clock != nil {
			config.Clock = options.clock
		}
		manager, err := peer.New(config)
		if err != nil {
			t.Fatal(err)
		}
		h.manager, h.handler = manager, manager
		peerConfig := peer.PeerConfig{Host: "remote.example.net", NoAutoReconnect: true}
		if frontend.initiator {
			peerConfig.Endpoints = []peer.Endpoint{{Network: "tcp", Address: listener.Addr().String()}}
		} else {
			server = &diam.Server{Dict: h.dict, Logger: logger, OnNewConnection: func(c diam.Conn) { native <- c }}
			if err := manager.BindServer(server); err != nil {
				t.Fatal(err)
			}
		}
		if err := manager.AddPeer(peerConfig); err != nil {
			t.Fatal(err)
		}
		h.send = func() <-chan parityApplicationResult {
			done := make(chan parityApplicationResult, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				answer, err := manager.Send(ctx, parityApplicationRequest(h.dict))
				done <- parityApplicationResult{answer, err}
			}()
			return done
		}
		h.closeCause = func(cause uint32) <-chan error {
			done := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				done <- manager.Close(ctx, sm.DisconnectCause(cause))
			}()
			return done
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
				t.Error(err)
			}
		})
		if err := manager.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else {
		if !frontend.initiator {
			settings.EnableWatchdog, settings.WatchdogInterval = true, interval
			settings.OnWatchdogConnEvent = func(_ diam.Conn, event sm.WatchdogEvent) { h.watchdog <- event }
		}
		admitted := make(chan diam.Conn, 1)
		settings.OnHandshake = func(conn diam.Conn, _ *smpeer.Metadata) {
			admitted <- conn
			ready.Do(func() { close(h.ready) })
		}
		state, err := sm.New(&settings)
		if err != nil {
			t.Fatal(err)
		}
		h.handler = state
		if options.application {
			answers := make(chan *diam.Message, 8)
			state.HandleIdx(diam.CommandIndex{AppID: contractApp, Code: contractCommand}, diam.HandlerFunc(func(_ diam.Conn, message *diam.Message) {
				answers <- message
			}))
			h.send = func() <-chan parityApplicationResult {
				done := make(chan parityApplicationResult, 1)
				go func() {
					tracker, ok := diam.ConnAs[interface{ PendingRequests() *diam.PendingRequests }](h.conn)
					if !ok {
						done <- parityApplicationResult{err: errors.New("native connection has no request tracker")}
						return
					}
					request := parityApplicationRequest(h.dict)
					write := tracker.PendingRequests().PrepareWrite(request.Header)
					defer write.Release()
					defer write.Cancel()
					if _, err := request.WriteTo(h.conn); err != nil {
						done <- parityApplicationResult{err: err}
						return
					}
					select {
					case answer := <-answers:
						done <- parityApplicationResult{answer: answer}
					case <-time.After(10 * time.Second):
						done <- parityApplicationResult{err: errors.New("owned application answer was not admitted")}
					}
				}()
				return done
			}
		}
		h.closeCause = func(cause uint32) <-chan error {
			done := make(chan error, 1)
			go func() { done <- state.Disconnect(h.conn, sm.DisconnectCause(cause), 10*time.Second) }()
			return done
		}
		if frontend.initiator {
			client := &sm.Client{Dict: h.dict, Handler: state, EnableWatchdog: true, WatchdogInterval: interval,
				RetransmitInterval: time.Hour, Logger: logger, OnWatchdogEvent: func(event sm.WatchdogEvent) { h.watchdog <- event }}
			done := make(chan error, 1)
			h.done = done
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() {
				var conn diam.Conn
				var err error
				if options.writeGate == nil {
					conn, err = client.DialContext(ctx, "tcp", listener.Addr().String(), nil)
				} else {
					var transport net.Conn
					transport, err = (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
					if err == nil {
						conn, err = client.NewConn(&parityReplyConn{Conn: transport, gate: options.writeGate}, listener.Addr().String())
					}
				}
				if conn != nil {
					// Cleanup registration is synchronized by receiving done below.
					t.Cleanup(conn.Close)
				}
				done <- err
			}()
		} else {
			server = &diam.Server{Dict: h.dict, Handler: state, Logger: logger, OnNewConnection: func(c diam.Conn) { native <- c }}
		}
		// The callback's channel publishes the connection before ready is closed.
		// The test consumes it only after the wire handshake has succeeded.
		t.Cleanup(func() {
			select {
			case conn := <-admitted:
				conn.Close()
			default:
			}
		})
		if handshake {
			defer func() { h.conn = parityAwait(t, admitted) }()
		}
	}
	if server != nil {
		served := make(chan error, 1)
		servedListener := listener
		if options.writeGate != nil {
			servedListener = &parityReplyListener{Listener: listener, gate: options.writeGate}
		}
		go func() { served <- server.Serve(servedListener) }()
		t.Cleanup(func() {
			_ = server.Close()
			if err := parityAwait(t, served); err != nil && !errors.Is(err, diam.ErrServerClosed) {
				t.Error(err)
			}
		})
	}
	if frontend.initiator {
		if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		h.wire, err = listener.Accept()
	} else {
		h.wire, err = net.DialTimeout("tcp", listener.Addr().String(), 10*time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	h.close = func() <-chan error { return h.closeCause(uint32(sm.DisconnectRebooting)) }
	if !frontend.initiator {
		h.conn = parityAwait(t, native)
	}
	t.Cleanup(func() { _ = h.wire.Close() })
	if handshake {
		if frontend.initiator {
			cer := h.read(t)
			if cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("initial message is not CER: %+v", cer.Header)
			}
			cea := contractBase(h.dict, diam.CapabilitiesExchange, false)
			cea.Header.HopByHopID, cea.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
			h.completedCEA = h.write(t, cea)
		} else {
			cer := contractBase(h.dict, diam.CapabilitiesExchange, true)
			h.write(t, cer)
			h.answer(t, cer, diam.Success)
		}
		parityAwait(t, h.ready)
		if h.done != nil {
			if err := parityAwait(t, h.done); err != nil {
				t.Fatal(err)
			}
		}
	}
	return h
}

func parityApplicationRequest(d *dict.Parser) *diam.Message {
	request := contractRequest(d)
	request.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("remote.example.net")))
	request.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	return request
}

func (h *parityTCP) write(t *testing.T, message *diam.Message) diam.Header {
	t.Helper()
	if err := h.wire.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := h.wire.Write(wire); err != nil || n != len(wire) {
		t.Fatalf("write=%d,%v; want %d bytes", n, err, len(wire))
	}
	header, err := diam.DecodeHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	return *header
}

func (h *parityTCP) read(t *testing.T) *diam.Message {
	t.Helper()
	if err := h.wire.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message, err := diam.ReadMessage(h.wire, h.dict)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func (h *parityTCP) answer(t *testing.T, request *diam.Message, code uint32) []byte {
	t.Helper()
	answer := h.read(t)
	if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.ApplicationID != request.Header.ApplicationID ||
		answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID ||
		answer.Header.CommandFlags&diam.RequestFlag != 0 || contractCode(t, answer) != code {
		t.Fatalf("answer=%v; want correlated %d answer to %+v", answer, code, request.Header)
	}
	wire, err := answer.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (h *parityTCP) barrier(t *testing.T) {
	t.Helper()
	request := contractBase(h.dict, diam.DeviceWatchdog, true)
	request.Header.HopByHopID, request.Header.EndToEndID = 0xba771e01, 0xba771e02
	h.write(t, request)
	h.answer(t, request, diam.Success)
}

func (h *parityTCP) eof(t *testing.T) {
	t.Helper()
	if err := h.wire.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := h.wire.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("closure=%d bytes,%v; want EOF without another reply", n, err)
	}
}

type parityDisposition struct {
	Kind      diam.ProtocolErrorKind
	Code      uint32
	Closing   bool
	Reply     diam.ProtocolReplyStatus
	ReplyCode uint32
}

func (h *parityTCP) event(t *testing.T, header diam.Header, want parityDisposition) parityDisposition {
	t.Helper()
	event := parityAwait(t, h.events)
	if event.Err == nil || !event.Message.HasHeader || event.Message.Header != header || event.Message.Stream != 0 || event.Conn == nil {
		t.Fatalf("protocol event lost message metadata: %+v; want %+v", event, header)
	}
	if h.conn != nil && h.conn != event.Conn {
		t.Fatal("protocol event attributed to a different connection")
	}
	h.conn = event.Conn
	got := parityDisposition{event.Err.Kind(), event.Err.ResultCode(), event.Closing, event.Reply, event.ReplyCode}
	if got != want {
		t.Fatalf("protocol disposition=%+v; want %+v", got, want)
	}
	return got
}

func (h *parityTCP) noEvents(t *testing.T) {
	t.Helper()
	select {
	case event := <-h.events:
		t.Fatalf("additional protocol event after wire barrier: %+v", event)
	default:
	}
}

// Config.QueueWrites selects Manager's queue-acceptance report. StateMachine
// and Client report completed writes. Assert that exact difference before
// comparing the remaining disposition; no other field is exempted.
func (f parityFrontend) replyDisposition(kind diam.ProtocolErrorKind, code uint32, reply bool, closing bool) parityDisposition {
	disposition := parityDisposition{Kind: kind, Code: code, Closing: closing}
	if reply {
		disposition.Reply, disposition.ReplyCode = diam.ProtocolReplyWritten, code
		if f.manager {
			disposition.Reply = diam.ProtocolReplyQueued
		}
	}
	return disposition
}

type parityObservation struct {
	Wire        []byte
	Disposition parityDisposition
}

func parityCompare(t *testing.T, baseline *parityObservation, got parityObservation) {
	t.Helper()
	// The caller already asserted the selected QueueWrites completion boundary.
	if got.Disposition.Reply == diam.ProtocolReplyQueued {
		got.Disposition.Reply = diam.ProtocolReplyWritten
	}
	if baseline.Wire == nil && baseline.Disposition.Kind == "" {
		*baseline = got
		return
	}
	if !bytes.Equal(baseline.Wire, got.Wire) || baseline.Disposition != got.Disposition {
		t.Fatalf("frontend divergence:\n got wire=%x disposition=%+v\nwant wire=%x disposition=%+v", got.Wire, got.Disposition, baseline.Wire, baseline.Disposition)
	}
}

func TestProtocolTCPParityOpen(t *testing.T) {
	tests := []struct {
		name    string
		message func(*testing.T, *dict.Parser) *diam.Message
		kind    diam.ProtocolErrorKind
		code    uint32
		reply   bool
	}{
		{"DWR", func(_ *testing.T, d *dict.Parser) *diam.Message { return contractBase(d, diam.DeviceWatchdog, true) }, "", diam.Success, true},
		{"DWRMissingRealm", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, true)
			contractDrop(m, avp.OriginRealm)
			return m
		}, diam.ProtocolInvalidRequest, diam.MissingAVP, true},
		{"DWRDuplicateHost", func(t *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, true)
			a := *contractField(t, m, avp.OriginHost)
			m.AddAVP(&a)
			return m
		}, diam.ProtocolInvalidRequest, diam.AVPOccursTooManyTimes, true},
		{"DWRHeader", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, true)
			m.Header.CommandFlags |= diam.ProxiableFlag
			return m
		}, diam.ProtocolInvalidHeader, diam.InvalidHDRBits, true},
		{"DWRWrongHost", func(t *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, true)
			contractField(t, m, avp.OriginHost).Data = datatype.DiameterIdentity("other.example.net")
			return m
		}, diam.ProtocolInvalidDWR, 0, false},
		{"DWRUnknownMandatory", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, true)
			m.AddAVP(diam.NewAVP(contractUnknown, avp.Mbit, 0, datatype.Unknown{0, 0, 0, 1}))
			return m
		}, diam.ProtocolUnsupportedAVP, diam.AVPUnsupported, true},
		{"RepeatedCER", func(_ *testing.T, d *dict.Parser) *diam.Message {
			return contractBase(d, diam.CapabilitiesExchange, true)
		}, diam.ProtocolUnexpectedMessage, 0, false},
		{"RepeatedCERInvalidBody", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.CapabilitiesExchange, true)
			contractDrop(m, avp.OriginRealm)
			return m
		}, diam.ProtocolUnexpectedMessage, 0, false},
		{"DWAMissingResult", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DeviceWatchdog, false)
			contractDrop(m, avp.ResultCode)
			return m
		}, diam.ProtocolInvalidDWA, diam.MissingAVP, false},
		{"UnownedDPA", func(_ *testing.T, d *dict.Parser) *diam.Message { return contractBase(d, diam.DisconnectPeer, false) }, diam.ProtocolUnexpectedMessage, 0, false},
		{"DPRWrongHost", func(t *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DisconnectPeer, true)
			contractField(t, m, avp.OriginHost).Data = datatype.DiameterIdentity("other.example.net")
			return m
		}, diam.ProtocolInvalidDPR, 0, false},
		{"DPRInvalidCause", func(t *testing.T, d *dict.Parser) *diam.Message {
			m := contractBase(d, diam.DisconnectPeer, true)
			contractField(t, m, avp.DisconnectCause).Data = datatype.Enumerated(3)
			return m
		}, diam.ProtocolInvalidRequest, diam.InvalidAVPValue, true},
		{"UnsupportedCommand", func(_ *testing.T, d *dict.Parser) *diam.Message { return contractRequest(d) }, diam.ProtocolUnsupportedCommand, diam.CommandUnsupported, true},
		{"UnsupportedApplication", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractRequest(d)
			m.Header.ApplicationID++
			return m
		}, diam.ProtocolUnsupportedApplication, diam.ApplicationUnsupported, true},
		{"ApplicationMissingRequired", func(_ *testing.T, d *dict.Parser) *diam.Message {
			m := contractRequest(d)
			contractDrop(m, contractRequired)
			return m
		}, diam.ProtocolInvalidRequest, diam.MissingAVP, true},
		{"UnownedApplicationAnswer", func(_ *testing.T, d *dict.Parser) *diam.Message { return contractRequest(d).Answer(diam.Success) }, diam.ProtocolUnexpectedMessage, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var baseline parityObservation
			for _, frontend := range parityFrontends {
				t.Run(frontend.name+"/QueueWrites="+fmt.Sprint(frontend.manager), func(t *testing.T) {
					h := parityStart(t, frontend, true)
					message := test.message(t, h.dict)
					header := h.write(t, message)
					var got parityObservation
					if test.reply {
						got.Wire = h.answer(t, message, test.code)
					}
					if test.kind != "" {
						got.Disposition = h.event(t, header, frontend.replyDisposition(test.kind, test.code, test.reply, false))
					}
					h.barrier(t)
					h.noEvents(t)
					parityCompare(t, &baseline, got)
				})
			}
		})
	}
}

func TestProtocolTCPParityAdmission(t *testing.T) {
	for _, command := range []uint32{contractCommand, diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(fmt.Sprint(command), func(t *testing.T) {
			var baseline parityObservation
			for _, frontend := range parityFrontends {
				t.Run(frontend.name, func(t *testing.T) {
					h := parityStart(t, frontend, false)
					if frontend.initiator {
						if cer := h.read(t); cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
							t.Fatalf("expected outgoing CER before admission: %+v", cer.Header)
						}
					}
					message := contractBase(h.dict, command, true)
					if command == contractCommand {
						message = contractRequest(h.dict)
					}
					header := h.write(t, message)
					got := parityObservation{Disposition: h.event(t, header, frontend.replyDisposition(diam.ProtocolHandshakeState, 0, false, true))}
					h.eof(t)
					select {
					case <-h.ready:
						t.Fatal("pre-handshake traffic admitted the connection")
					default:
					}
					if h.done != nil {
						if err := parityAwait(t, h.done); err == nil {
							t.Fatal("Client returned an admitted connection after rejecting pre-handshake traffic")
						}
					}
					h.noEvents(t)
					parityCompare(t, &baseline, got)
				})
			}
		})
	}
}

func TestProtocolTCPParityWaitCEA(t *testing.T) {
	for _, mismatch := range []string{"hop", "end", "malformed-unowned"} {
		t.Run(mismatch, func(t *testing.T) {
			var baseline parityObservation
			for _, frontend := range parityFrontends {
				if !frontend.initiator {
					continue
				}
				t.Run(frontend.name, func(t *testing.T) {
					h := parityStart(t, frontend, false)
					cer := h.read(t)
					cea := contractBase(h.dict, diam.CapabilitiesExchange, false)
					cea.Header.HopByHopID, cea.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
					if mismatch == "end" {
						cea.Header.EndToEndID++
					} else {
						cea.Header.HopByHopID++
					}
					if mismatch == "malformed-unowned" {
						contractDrop(cea, avp.OriginRealm)
					}
					header := h.write(t, cea)
					got := parityObservation{Disposition: h.event(t, header, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))}
					select {
					case <-h.ready:
						t.Fatal("uncorrelated CEA released admission")
					default:
					}
					// The correlated replacement is a protocol fence: a reply to the
					// unowned answer would precede the following DWA on the wire.
					cea = contractBase(h.dict, diam.CapabilitiesExchange, false)
					cea.Header.HopByHopID, cea.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
					h.write(t, cea)
					parityAwait(t, h.ready)
					if h.done != nil {
						if err := parityAwait(t, h.done); err != nil {
							t.Fatal(err)
						}
					}
					h.barrier(t)
					h.noEvents(t)
					parityCompare(t, &baseline, got)
				})
			}
		})
	}
}

func TestProtocolTCPParityLocalClosing(t *testing.T) {
	for _, result := range []uint32{diam.Success, diam.UnableToComply} {
		t.Run(fmt.Sprint(result), func(t *testing.T) {
			var baselineDPR, baselineDPA []byte
			for _, frontend := range parityFrontends {
				t.Run(frontend.name, func(t *testing.T) {
					h := parityStart(t, frontend, true)
					done := h.close()
					dpr := h.read(t)
					if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags != diam.RequestFlag || dpr.Header.ApplicationID != 0 {
						t.Fatalf("local disconnect did not send DPR: %+v", dpr.Header)
					}
					cause := contractField(t, dpr, avp.DisconnectCause)
					if cause.Data != datatype.Enumerated(sm.DisconnectRebooting) {
						t.Fatalf("local disconnect cause=%v", cause.Data)
					}
					// Identifier allocation belongs to each adapter. Compare every
					// other transmitted byte; answers below use the actual lease.
					hop, end := dpr.Header.HopByHopID, dpr.Header.EndToEndID
					dpr.Header.HopByHopID, dpr.Header.EndToEndID = 0, 0
					wire, err := dpr.Serialize()
					if err != nil {
						t.Fatal(err)
					}
					if baselineDPR == nil {
						baselineDPR = wire
					} else if !bytes.Equal(baselineDPR, wire) {
						t.Fatalf("local DPR differs: got=%x want=%x", wire, baselineDPR)
					}
					dpr.Header.HopByHopID, dpr.Header.EndToEndID = hop, end
					// Closing rejects new work before header, grammar, mandatory-AVP
					// validation and application dispatch. A valid crossed DPR below
					// fences every silent drop without a silence timeout.
					for _, message := range []*diam.Message{
						contractRequest(h.dict), contractRequest(h.dict).Answer(diam.Success),
						contractBase(h.dict, diam.CapabilitiesExchange, true), contractBase(h.dict, diam.CapabilitiesExchange, false),
						contractBase(h.dict, diam.DeviceWatchdog, true), contractBase(h.dict, diam.DeviceWatchdog, false),
						diam.NewMessage(contractCommand, diam.RequestFlag|diam.ErrorFlag, contractApp, 7, 8, h.dict),
					} {
						h.write(t, message)
					}
					for _, fault := range []string{"hop", "end", "host", "grammar"} {
						answer := contractBase(h.dict, diam.DisconnectPeer, false)
						answer.Header.HopByHopID, answer.Header.EndToEndID = hop, end
						kind, code := diam.ProtocolUnexpectedMessage, uint32(0)
						switch fault {
						case "hop":
							answer.Header.HopByHopID++
						case "end":
							answer.Header.EndToEndID++
						case "host":
							contractField(t, answer, avp.OriginHost).Data = datatype.DiameterIdentity("other.example.net")
						case "grammar":
							contractDrop(answer, avp.ResultCode)
							kind, code = diam.ProtocolInvalidDPA, diam.MissingAVP
						}
						header := h.write(t, answer)
						h.event(t, header, frontend.replyDisposition(kind, code, false, false))
						select {
						case err := <-done:
							t.Fatalf("%s DPA completed local disconnect: %v", fault, err)
						default:
						}
					}
					crossed := contractBase(h.dict, diam.DisconnectPeer, true)
					h.write(t, crossed)
					wire = h.answer(t, crossed, diam.Success)
					if baselineDPA == nil {
						baselineDPA = wire
					} else if !bytes.Equal(baselineDPA, wire) {
						t.Fatalf("crossed DPR reply differs: got=%x want=%x", wire, baselineDPA)
					}
					h.noEvents(t)
					answer := contractBase(h.dict, diam.DisconnectPeer, false)
					answer.Header.HopByHopID, answer.Header.EndToEndID = hop, end
					contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(result)
					header := h.write(t, answer)
					if result != diam.Success {
						h.event(t, header, frontend.replyDisposition(diam.ProtocolPeerRejected, result, false, true))
					}
					err = parityAwait(t, done)
					// Disconnect exposes this connection's DPA result. Manager.Close
					// completes its manager-wide shutdown and reports peer rejection
					// through OnProtocolError above. These API results belong to the
					// adapters; the core completes the same Closed disposition.
					if frontend.manager || result == diam.Success {
						if err != nil {
							t.Fatalf("completed disconnect returned %v", err)
						}
					} else if err == nil || err.Error() != fmt.Sprintf("DPA Result-Code %d", result) {
						t.Fatalf("rejected DPA disconnect result=%v; want DPA Result-Code %d", err, result)
					}
					h.eof(t)
					h.noEvents(t)
				})
			}
		})
	}
}

func TestProtocolTCPParityClosingApplicationOwnership(t *testing.T) {
	var baselineBusy, baselineDrained []byte
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true, true)
			application := h.send()
			request := h.read(t)
			if request.Header.CommandCode != contractCommand || request.Header.ApplicationID != contractApp || request.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("outbound application request=%+v", request.Header)
			}
			done := h.close()
			dpr := h.read(t)
			if dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("local disconnect did not send DPR: %+v", dpr.Header)
			}
			for _, mismatch := range []string{"hop", "end", "command", "application"} {
				answer := request.Answer(diam.Success)
				switch mismatch {
				case "hop":
					answer.Header.HopByHopID++
				case "end":
					answer.Header.EndToEndID++
				case "command":
					answer.Header.CommandCode++
				case "application":
					answer.Header.ApplicationID++
				}
				h.write(t, answer)
			}
			// Frozen ownership, supplied by the adapters in Input.Ownership and
			// Frozen.InFlight, admits only the actual published application answer.
			// A crossed DPR fences the four silent mismatches and reports that
			// the original request remains likely in flight.
			crossed := contractBase(h.dict, diam.DisconnectPeer, true)
			h.write(t, crossed)
			busy := h.answer(t, crossed, diam.UnableToComply)
			if baselineBusy == nil {
				baselineBusy = busy
			} else if !bytes.Equal(baselineBusy, busy) {
				t.Fatalf("in-flight DPA differs: got=%x want=%x", busy, baselineBusy)
			}
			select {
			case result := <-application:
				t.Fatalf("uncorrelated Closing answer completed application request: %+v", result)
			default:
			}
			answer := request.Answer(diam.Success)
			h.write(t, answer)
			result := parityAwait(t, application)
			if result.err != nil || result.answer == nil || *result.answer.Header != *answer.Header || contractCode(t, result.answer) != diam.Success {
				t.Fatalf("owned Closing application answer=%+v; want %+v", result, answer.Header)
			}
			crossed.Header.HopByHopID++
			crossed.Header.EndToEndID++
			h.write(t, crossed)
			drained := h.answer(t, crossed, diam.Success)
			if baselineDrained == nil {
				baselineDrained = drained
			} else if !bytes.Equal(baselineDrained, drained) {
				t.Fatalf("drained DPA differs: got=%x want=%x", drained, baselineDrained)
			}
			h.noEvents(t)
			dpa := contractBase(h.dict, diam.DisconnectPeer, false)
			dpa.Header.HopByHopID, dpa.Header.EndToEndID = dpr.Header.HopByHopID, dpr.Header.EndToEndID
			h.write(t, dpa)
			if err := parityAwait(t, done); err != nil {
				t.Fatalf("disconnect after application drain: %v", err)
			}
			h.eof(t)
			h.noEvents(t)
		})
	}
}

func TestProtocolTCPParityCompletedCEA(t *testing.T) {
	for _, correlation := range []string{"duplicate", "hop", "end"} {
		for _, shape := range []string{"valid", "missing", "flags"} {
			for _, frontend := range parityFrontends {
				if !frontend.initiator {
					continue
				}
				t.Run(correlation+"/"+shape+"/"+frontend.name, func(t *testing.T) {
					h := parityStart(t, frontend, true)
					cea := contractBase(h.dict, diam.CapabilitiesExchange, false)
					cea.Header.HopByHopID, cea.Header.EndToEndID = h.completedCEA.HopByHopID, h.completedCEA.EndToEndID
					if correlation == "hop" {
						cea.Header.HopByHopID++
					}
					if correlation == "end" {
						cea.Header.EndToEndID++
					}
					if shape == "missing" {
						contractDrop(cea, avp.OriginRealm)
					}
					if shape == "flags" {
						cea.Header.CommandFlags |= diam.ProxiableFlag
					}
					before := len(h.logs.Records())
					header := h.write(t, cea)
					h.event(t, header, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))
					h.barrier(t)
					h.noEvents(t)
					if correlation == "duplicate" && len(h.logs.Records()) != before {
						t.Fatal("completed duplicate CEA was logged")
					}
				})
			}
		}
	}
}

func TestProtocolTCPParityUnownedDWA(t *testing.T) {
	for _, result := range []uint32{diam.Success, diam.UnableToComply} {
		for _, frontend := range parityFrontends {
			t.Run(fmt.Sprintf("%d/%s", result, frontend.name), func(t *testing.T) {
				h := parityStart(t, frontend, true)
				dwa := contractBase(h.dict, diam.DeviceWatchdog, false)
				contractField(t, dwa, avp.ResultCode).Data = datatype.Unsigned32(result)
				before := len(h.logs.Records())
				header := h.write(t, dwa)
				h.event(t, header, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))
				h.barrier(t)
				h.noEvents(t)
				found := false
				for _, record := range h.logs.Records()[before:] {
					detail := record.Message + " " + fmt.Sprint(logtest.Attr(record, "error").Any())
					if strings.Contains(detail, "DWA") && strings.Contains(detail, "mismatch") {
						found = true
					}
				}
				if !found {
					t.Fatal("unowned DWA lost its correlation diagnostic")
				}
				for {
					select {
					case event := <-h.watchdog:
						if event == sm.WatchdogInvalidAnswer || event == sm.WatchdogAnswerReceived {
							t.Fatalf("unowned DWA emitted watchdog answer callback %s", event)
						}
					default:
						return
					}
				}
			})
		}
	}
}

// Invalid CER headers share the same rejection policy before and after admission.
func TestProtocolTCPParityCERHeader(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			for _, hooks := range []bool{false, true} {
				// Manager owns capability callbacks and rejects Settings.OnCER/OnCEA.
				if frontend.manager && hooks {
					continue
				}
				t.Run(fmt.Sprintf("Hooks=%t", hooks), func(t *testing.T) {
					for _, open := range []bool{false, true} {
						if !open && frontend.initiator {
							continue
						}
						t.Run(fmt.Sprintf("Open=%t", open), func(t *testing.T) {
							var baseline parityDisposition
							var baselineLogs []string
							var baselineRan bool
							for _, shape := range []string{"ApplicationID", "Proxiable", "Error", "Repeated"} {
								if !open && shape != "ApplicationID" && shape != "Proxiable" {
									continue
								}
								t.Run(shape, func(t *testing.T) {
									var cerCalls, ceaCalls atomic.Int32
									options := paritySettings{}
									if hooks {
										options.onCER = func(diam.Conn, *diam.Message) { cerCalls.Add(1) }
										options.onCEA = func(diam.Conn, *diam.Message) { ceaCalls.Add(1) }
									}
									h := parityStartConfigured(t, frontend, open, options)
									beforeCER, beforeCEA := cerCalls.Load(), ceaCalls.Load()
									if hooks && open {
										wantCER := int32(1)
										if frontend.initiator {
											wantCER = 0
										}
										wantCEA := int32(1)
										if frontend.initiator {
											wantCEA = 0
										}
										if beforeCER != wantCER || beforeCEA != wantCEA {
											t.Fatalf("handshake callbacks CER/CEA=%d/%d; want %d/%d", beforeCER, beforeCEA, wantCER, wantCEA)
										}
									}
									beforeLogs := len(h.logs.Records())
									cer := contractBase(h.dict, diam.CapabilitiesExchange, true)
									cer.Header.HopByHopID, cer.Header.EndToEndID = 0x45112233, 0x45445566
									switch shape {
									case "ApplicationID":
										cer.Header.ApplicationID = contractApp
									case "Proxiable":
										cer.Header.CommandFlags |= diam.ProxiableFlag
									case "Error":
										cer.Header.CommandFlags |= diam.ErrorFlag
									}
									header := h.write(t, cer)
									if shape == "Repeated" {
										h.event(t, header, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))
										h.barrier(t)
										h.noEvents(t)
										wantCER := beforeCER
										if hooks {
											wantCER++
										}
										if cerCalls.Load() != wantCER || ceaCalls.Load() != beforeCEA {
											t.Fatalf("repeated callbacks CER/CEA=%d/%d; want %d/%d", cerCalls.Load(), ceaCalls.Load(), wantCER, beforeCEA)
										}
										found := false
										for _, record := range h.logs.Records()[beforeLogs:] {
											if record.Level == slog.LevelWarn {
												found = true
											}
										}
										if !found {
											t.Fatal("valid repeated CER did not retain its warning")
										}
										return
									}
									answer := h.read(t)
									wantFlags := uint8(diam.ErrorFlag) | header.CommandFlags&diam.ProxiableFlag
									if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags != wantFlags || answer.Header.ApplicationID != 0 ||
										answer.Header.HopByHopID != header.HopByHopID || answer.Header.EndToEndID != header.EndToEndID || contractCode(t, answer) != diam.InvalidHDRBits {
										t.Fatalf("invalid CER answer=%v; want 3008 flags=%02x app=0 IDs=%08x/%08x", answer, wantFlags, header.HopByHopID, header.EndToEndID)
									}
									if host := contractField(t, answer, avp.OriginHost).Data; host != datatype.DiameterIdentity("local.example.net") {
										t.Fatalf("Origin-Host=%v", host)
									}
									if realm := contractField(t, answer, avp.OriginRealm).Data; realm != datatype.DiameterIdentity("example.net") {
										t.Fatalf("Origin-Realm=%v", realm)
									}
									disposition := h.event(t, header, frontend.replyDisposition(diam.ProtocolInvalidHeader, diam.InvalidHDRBits, true, true))
									h.eof(t)
									h.noEvents(t)
									wantCEA := beforeCEA
									if hooks {
										wantCEA++
									}
									if cerCalls.Load() != beforeCER || ceaCalls.Load() != wantCEA {
										t.Fatalf("invalid CER callbacks CER/CEA=%d/%d; want %d/%d", cerCalls.Load(), ceaCalls.Load(), beforeCER, wantCEA)
									}
									var logs []string
									for _, record := range h.logs.Records()[beforeLogs:] {
										if record.Level >= slog.LevelWarn {
											logs = append(logs, fmt.Sprintf("%s/%s", record.Level, record.Message))
										}
									}
									if shape == "ApplicationID" {
										baseline, baselineLogs, baselineRan = disposition, logs, true
									} else if baselineRan && (disposition != baseline || !reflect.DeepEqual(logs, baselineLogs)) {
										t.Fatalf("header rejection observers/logs differ from ApplicationID control: got %+v %v; want %+v %v", disposition, logs, baseline, baselineLogs)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
