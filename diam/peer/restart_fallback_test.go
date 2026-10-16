package peer

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type restartEvent struct {
	data []byte
	err  error
}
type restartScriptListener struct {
	conn     net.Conn
	closed   chan struct{}
	accepted bool
	once     sync.Once
}

func (l *restartScriptListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *restartScriptListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *restartScriptListener) Addr() net.Addr { return l.conn.LocalAddr() }

func TestManagerSecondCERKeepsConnectionOpen(t *testing.T) {
	for _, renewal := range []bool{false} {
		t.Run(map[bool]string{false: "default", true: "renewal flag"}[renewal], func(t *testing.T) {
			records := logtest.New()
			events := make(chan diam.ProtocolErrorEvent, 8)
			settings := testSettings("local.example.net")
			settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
			m, err := New(Config{Settings: settings, Logger: records.Logger()})
			if err != nil {
				t.Fatal(err)
			}
			if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &diam.Server{Logger: records.Logger(), RenewAcceptedCER: renewal, MaxConcurrentHandlers: 8}
			srv.Dict = m.cfg.Settings.Dict
			if err = m.BindServer(srv); err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(l) }()
			t.Cleanup(func() { closeManager(t, m, srv) })
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			capabilities := testBase("known.example.net")
			capabilities.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
			cer, err := base.BuildCER(m.dictionary(), capabilities)
			if err != nil {
				t.Fatal(err)
			}
			write(t, c, cer)
			if a := read(t, c); code(t, a) != diam.Success {
				t.Fatal(a)
			}
			awaitState(t, m, ROpen)
			before := m.Peers()[0]
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			pending := sendAsync(m, ctx, outboundRequest("known.example.net", "example.net"))
			request := read(t, c)
			if request.Header.CommandCode != 272 || request.Header.ApplicationID != 4 || request.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("application request=%+v", request.Header)
			}
			second := capabilitiesExchangeRequest(t)
			write(t, c, second)
			e := protocolErrorReceive(t, events)
			if err = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			n, err := c.Read(b[:])
			var timeout net.Error
			if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("second CER must send no answer and retain the connection: read=%d error=%v", n, err)
			}
			protocolErrorCheck(t, e, e.Conn, *second.Header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0, 0)
			if e.Conn.Closed() || e.Conn.RemoteAddr().String() != c.LocalAddr().String() {
				t.Fatal("notification did not retain the admitted connection")
			}
			select {
			case got := <-pending:
				t.Fatalf("second CER completed pending request: %+v", got)
			default:
			}
			dwr := watchdogRequest(t)
			write(t, c, dwr)
			dwa := read(t, c)
			if code(t, dwa) != diam.Success || dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.CommandFlags&diam.RequestFlag != 0 || dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID {
				t.Fatalf("watchdog after second CER=%+v", dwa.Header)
			}
			write(t, c, request.Answer(diam.Success))
			select {
			case got := <-pending:
				if got.err != nil || got.answer == nil || code(t, got.answer) != diam.Success || got.answer.Header.HopByHopID != request.Header.HopByHopID {
					t.Fatalf("pending application request after second CER: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal("application answer was not delivered after second CER")
			}
			// A new application request must still select this same generation.
			next := sendAsync(m, ctx, outboundRequest("known.example.net", "example.net"))
			request = read(t, c)
			write(t, c, request.Answer(diam.Success))
			select {
			case got := <-next:
				if got.err != nil || got.answer == nil || code(t, got.answer) != diam.Success {
					t.Fatalf("following application request: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal("following application request did not complete")
			}
			if after := m.Peers()[0]; !reflect.DeepEqual(after, before) {
				t.Fatalf("second CER changed peer: before=%+v after=%+v", before, after)
			}
			logs := records.Records()
			if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "peer: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible" || logtest.Attr(logs[0], "message.hop_by_hop_id").Uint64() != uint64(second.Header.HopByHopID) {
				t.Fatalf("second CER logs=%v", logs)
			}
			select {
			case extra := <-events:
				t.Fatalf("extra protocol notification: %+v", extra)
			default:
			}
		})
	}
}

func TestManagerSecondCERPreservesPendingRequests(t *testing.T) {
	for _, state := range []PeerState{IOpen, ROpen} {
		for _, callback := range []bool{false, true} {
			t.Run(string(state)+map[bool]string{false: "/without callback", true: "/with callback"}[callback], func(t *testing.T) {
				m, actors, sessions := outboundTestManager(t)
				a, s := actors[0], sessions[0]
				records := logtest.New()
				m.cfg.Logger, m.cfg.Clock = records.Logger(), &fakeClock{}
				a.state, a.i, a.r = state, nil, nil
				if state == IOpen {
					a.i = s
				} else {
					a.r = s
				}
				a.publish(nil)
				var events []diam.ProtocolErrorEvent
				if callback {
					m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events = append(events, e) }
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				pending := sendAsync(m, ctx, outboundRequest("a.example.net", "example.net"))
				request := nextWrite(t, s)
				m.pendingMu.Lock()
				owner := m.pending[s][request.Header.HopByHopID]
				m.pendingMu.Unlock()
				a.sendWatchdog()
				probe := nextWrite(t, s)
				// The probe publication arms the core timer.
				before, meta, connContext := a.snapshot(), a.meta, s.c.Context()
				second := capabilitiesExchangeRequest(t)
				a.onWire(event{kind: wireEvent, s: s, msg: second})
				if s.c.Closed() || a.state != state || a.active != s || a.meta != meta || s.c.Context() != connContext || !reflect.DeepEqual(a.snapshot(), before) {
					t.Fatal("second CER changed the admitted session")
				}
				select {
				case <-s.closed:
					t.Fatal("second CER closed session workers")
				default:
				}
				if len(s.writes) != 0 {
					t.Fatal("second CER queued an answer")
				}
				if !fixtureWatchdog(a).Pending || a.publishedWatchdog() != WatchdogOkay || fixtureControl(a, diam.DeviceWatchdog).Reservation.Hop != probe.Header.HopByHopID || fixtureControl(a, diam.DeviceWatchdog).Reservation.End != probe.Header.EndToEndID || fixtureWatchdogTimer(a) == nil {
					t.Fatal("second CER changed the pending watchdog")
				}
				m.pendingMu.Lock()
				retained := m.pending[s][request.Header.HopByHopID] == owner && owner != nil && !owner.done && !owner.failovering && owner.current == s
				_, control := m.controls[s][probe.Header.HopByHopID]
				m.pendingMu.Unlock()
				if !retained || !control {
					t.Fatal("second CER released pending ownership")
				}
				dwa, err := base.BuildDWA(probe, testBase("a.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				a.onWire(event{kind: wireEvent, s: s, msg: dwa})
				if fixtureWatchdog(a).Pending || a.publishedWatchdog() != WatchdogOkay {
					t.Fatal("pending watchdog did not accept DWA after second CER")
				}
				a.onWire(event{kind: wireEvent, s: s, msg: request.Answer(diam.Success)})
				select {
				case got := <-pending:
					if got.err != nil || got.answer == nil || code(t, got.answer) != diam.Success {
						t.Fatalf("pending application request: %+v", got)
					}
				case <-ctx.Done():
					t.Fatal("pending application request did not complete")
				}
				logs := records.Records()
				if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "peer: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible" {
					t.Fatalf("second CER logs=%v", logs)
				}
				if callback {
					if len(events) != 1 {
						t.Fatalf("protocol notifications=%d want 1", len(events))
					}
					protocolErrorCheck(t, events[0], s.c, *second.Header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
				}
			})
		}
	}
}
