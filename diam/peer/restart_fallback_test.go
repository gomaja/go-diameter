package peer

import (
	"context"
	"errors"
	"io"
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
type restartScriptConn struct {
	net.Conn
	events  chan restartEvent
	pending []byte
	closed  chan struct{}
	once    sync.Once
}

func (c *restartScriptConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case event := <-c.events:
			if event.err != nil {
				return 0, event.err
			}
			c.pending = event.data
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *restartScriptConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *restartScriptConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}
func (c *restartScriptConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 43868}
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

func TestManagerRestartClosesPhysicalConnection(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "before CER", true: "Open"}[admitted], func(t *testing.T) {
			records := logtest.New()
			manager, err := New(Config{Logger: records.Logger(), Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			if err = manager.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
				t.Fatal(err)
			}
			local, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			transport := &restartScriptConn{Conn: local, events: make(chan restartEvent, 2), closed: make(chan struct{})}
			listener := &restartScriptListener{conn: transport, closed: make(chan struct{})}
			accepted := make(chan diam.Conn, 1)
			srv := &diam.Server{Logger: records.Logger(), RenewAcceptedCER: true, OnNewConnection: func(c diam.Conn) { accepted <- c }}
			if err = manager.BindServer(srv); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(listener) }()
			defer func() {
				closeManager(t, manager, srv)
				if err := <-done; !errors.Is(err, diam.ErrServerClosed) {
					t.Error(err)
				}
			}()
			c := <-accepted
			if _, ok := diam.HandlerAs[diam.RetireHandler](manager); ok {
				t.Fatal("Manager must remain outside renewal scope")
			}
			if admitted {
				b, err := reviewCER(t).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				transport.events <- restartEvent{data: b}
				if a := read(t, remote); code(t, a) != diam.Success {
					t.Fatal(a)
				}
			}
			// Closure is expected; a peer that has already closed needs no deadline.
			if err := remote.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			transport.events <- restartEvent{err: &diam.TransportRestartError{AssociationID: 81}}
			if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("restart retained Manager socket: %v", err)
			}
			notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
			if !ok {
				t.Fatal("CloseNotifier missing")
			}
			select {
			case <-notifier.CloseNotify():
			case <-time.After(time.Second):
				t.Fatal("Manager pending owners not notified")
			}
			if !c.Closed() {
				t.Fatal("Manager generation retained")
			}
			found := false
			for _, record := range records.Records() {
				if record.Message == "diam: transport restart without retirement handler; closing connection" {
					found = true
				}
			}
			if !found {
				t.Fatal("fallback close not logged")
			}
		})
	}
}

// RFC 6733 §5.6: a CER on the admitted connection has no state-table row.
func TestManagerSecondCERKeepsConnectionOpen(t *testing.T) {
	for _, renewal := range []bool{false, true} {
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
			second := reviewCER(t)
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
			dwr := reviewDWR(t)
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
			if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "peer: ignoring CER on admitted connection; accepted CER renewal is not supported" || logtest.Attr(logs[0], "message.hop_by_hop_id").Uint64() != uint64(second.Header.HopByHopID) {
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
				a.armWatchdog()
				before, meta, connContext := a.snapshot(), a.meta, s.c.Context()
				second := reviewCER(t)
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
				if !a.pendingWatchdog || a.watchdog != WatchdogOkay || a.watchdogHop != probe.Header.HopByHopID || a.watchdogEnd != probe.Header.EndToEndID || a.watchdogGen != s.gen || a.wdTimer == nil {
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
				if a.pendingWatchdog || a.watchdog != WatchdogOkay {
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
				if len(logs) != 1 || logs[0].Level != slog.LevelWarn || logs[0].Message != "peer: ignoring CER on admitted connection; accepted CER renewal is not supported" {
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
