package sm

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// RFC 3539 §3.4.1 [2] and the #108 receive policy: invalid decoded
// traffic resets Tw, but cannot restore health or credit the outstanding DWR.
func TestAcceptedCoreInvalidActivityTCP(t *testing.T) {
	for _, fault := range []string{"repeated-cer", "malformed-repeated-cer", "decode", "header", "grammar", "application", "bound-host", "bound-host-dpr", "unsolicited-cea", "unsolicited-dpa"} {
		t.Run(fault, func(t *testing.T) {
			var events <-chan acceptedWatchdogEvent
			p := newProtocolWire(t, func(cfg *Settings) {
				cfg.EnableWatchdog = true
				cfg.WatchdogInterval = 200 * time.Millisecond
				cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
				events = acceptedWatchdogEvents(cfg)
			}, true)
			probe := acceptedWatchdogOnWire(t, p.peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
			awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
			time.Sleep(120 * time.Millisecond)
			m := regressionDWR(t)
			answer := true
			switch fault {
			case "repeated-cer", "malformed-repeated-cer":
				m = regressionCER(t, p.conn.Dictionary(), 1001)
				m.AVP = nil
				answer = false
				if fault == "malformed-repeated-cer" {
					m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
				}
			case "decode":
				m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			case "header":
				m.Header.ApplicationID = 9
			case "grammar":
				m.AVP = nil
			case "application":
				m = diam.NewMessage(0xfedc, diam.RequestFlag, 0xfefe, 123, 124, p.conn.Dictionary())
			case "bound-host", "bound-host-dpr":
				if fault == "bound-host-dpr" {
					m.Header.CommandCode = diam.DisconnectPeer
					m.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
				}
				m.AVP[0].Data = datatype.DiameterIdentity("another.example")
				answer = false
			case "unsolicited-cea":
				// Use the normal capability builder to retain complete grammar.
				var err error
				m, err = buildSuccessCEA(p.sm, p.conn, regressionCER(t, p.conn.Dictionary(), 1001))
				if err != nil {
					t.Fatal(err)
				}
				answer = false
			case "unsolicited-dpa":
				m = acceptedDWA(t, probe, diam.Success)
				m.Header.CommandCode = diam.DisconnectPeer
				answer = false
			}
			p.send(t, m)
			if answer {
				if _, err := diam.ReadMessage(p.peer, p.conn.Dictionary()); err != nil {
					t.Fatal(err)
				}
			}
			_ = protocolEvent(t, p.events)
			select {
			case e := <-events:
				t.Fatalf("invalid activity emitted %s", e.event)
			case <-time.After(120 * time.Millisecond):
			}
			// A real, correlated successful answer is the positive control.
			valid := acceptedDWA(t, probe, diam.Success)
			setWireIdentity(t, valid, avp.OriginHost, "peer.example")
			setWireIdentity(t, valid, avp.OriginRealm, "example")
			p.send(t, valid)
			awaitAcceptedEvent(t, events, WatchdogAnswerReceived, p.conn)
			awaitAcceptedEvent(t, events, WatchdogRecovered, p.conn)
		})
	}
}

// Hooks may change AVPs, but RFC 6733 §§3, 6.2.1 exchange coordinates
// belong to the continuation selected before the hook.
func TestAcceptedCoreHookCoordinatesTCP(t *testing.T) {
	for _, command := range []string{"CER", "DWR"} {
		for _, coordinate := range []string{"command", "application", "direction", "hop", "end"} {
			t.Run(fmt.Sprintf("%s/%s", command, coordinate), func(t *testing.T) {
				p := newProtocolWire(t, func(cfg *Settings) {
					hook := func(_ diam.Conn, m *diam.Message) {
						switch coordinate {
						case "command":
							m.Header.CommandCode++
						case "application":
							m.Header.ApplicationID++
						case "direction":
							m.Header.CommandFlags ^= diam.RequestFlag
						case "hop":
							m.Header.HopByHopID++
						case "end":
							m.Header.EndToEndID++
						}
					}
					if command == "CER" {
						cfg.OnCER = hook
					} else {
						cfg.OnDWR = hook
					}
				}, command == "DWR")
				m := regressionDWR(t)
				if command == "CER" {
					m = regressionCER(t, p.conn.Dictionary(), 1001)
				}
				p.send(t, m)
				var b [1]byte
				if n, err := p.peer.Read(b[:]); n != 0 || err != io.EOF {
					t.Fatalf("coordinate-changing hook: bytes=%x err=%v, want closure", b[:n], err)
				}
				_ = protocolEvent(t, p.events)
				logs := p.logs.Records()
				if len(logs) != 1 || logs[0].Level != slog.LevelError {
					t.Fatalf("hook failure logs=%v", logs)
				}
			})
		}
	}
}

// Block the actual TCP publication after the native gate admits the probe.
// RFC 3539 Appendix A permits one tentative probe, and #108 requires expiry
// to remain live while the selected writer has not completed publication.
type acceptedCoreBlockedListener struct {
	net.Listener
	entered, release chan struct{}
	attempts         *atomic.Int32
	once             *sync.Once
}

func (l acceptedCoreBlockedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &acceptedCoreBlockedTCP{Conn: c, entered: l.entered, release: l.release, attempts: l.attempts, once: l.once}, nil
}

type acceptedCoreBlockedTCP struct {
	net.Conn
	entered, release chan struct{}
	attempts         *atomic.Int32
	once             *sync.Once
}

func (c *acceptedCoreBlockedTCP) Write(b []byte) (int, error) {
	if h, err := diam.DecodeHeader(b); err == nil && h.CommandCode == diam.DeviceWatchdog && h.CommandFlags&diam.RequestFlag != 0 {
		c.attempts.Add(1)
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return c.Conn.Write(b)
}

func TestAcceptedCoreTentativeProbeTCP(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var attempts atomic.Int32
	var events <-chan acceptedWatchdogEvent
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := testMessageErrorSettings(testDict)
	cfg.EnableWatchdog = true
	cfg.WatchdogInterval = 80 * time.Millisecond
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	events = acceptedWatchdogEvents(cfg)
	p := &protocolWire{sm: mustNewStateMachine(t, cfg, testDict), events: make(chan diam.ProtocolErrorEvent, 16), logs: logtest.New()}
	cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan diam.Conn, 1)
	server := &diam.Server{Handler: p.sm, Dict: testDict, MaxConcurrentHandlers: -1, Logger: p.logs.Logger(), OnNewConnection: func(c diam.Conn) { accepted <- c }}
	serving := make(chan error, 1)
	go func() {
		serving <- server.Serve(acceptedCoreBlockedListener{listener, entered, release, &attempts, &once})
	}()
	t.Cleanup(func() { _ = server.Close(); <-serving })
	p.peer, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.peer.Close() })
	if err := p.peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	p.conn = protocolGenerationAwait(t, accepted)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	writeValidSMErrorCER(t, p.peer)
	if m, err := diam.ReadMessage(p.peer, p.conn.Dictionary()); err != nil || !testResultCode(m, diam.Success) {
		t.Fatalf("CEA=%v err=%v", m, err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("DWR writer did not block")
	}
	admitted := make(chan struct{}, 1)
	p.sm.HandleIdx(diam.CommandIndex{Code: 0xeeff, Request: false}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { admitted <- struct{}{} }))
	p.send(t, diam.NewMessage(0xeeff, 0, 0, 99, 100, p.conn.Dictionary()))
	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("activity blocked behind DWR writer")
	}
	time.Sleep(3 * 80 * time.Millisecond)
	if attempts.Load() != 1 || p.conn.Closed() {
		t.Fatalf("unpublished probe: attempts=%d closed=%t", attempts.Load(), p.conn.Closed())
	}
	select {
	case e := <-events:
		t.Fatalf("unpublished probe emitted %s", e.event)
	default:
	}
	close(release)
	probe := acceptedWatchdogOnWire(t, p.peer)
	awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
	valid := acceptedDWA(t, probe, diam.Success)
	setWireIdentity(t, valid, avp.OriginHost, "peer.example")
	setWireIdentity(t, valid, avp.OriginRealm, "example")
	p.send(t, valid)
	awaitAcceptedEvent(t, events, WatchdogAnswerReceived, p.conn)
	if attempts.Load() != 1 {
		t.Fatalf("duplicate tentative probe: %d", attempts.Load())
	}
}
