package peer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type consumingErrorHandler struct{ *Manager }

func (h consumingErrorHandler) HandleMessageError(c diam.Conn, msg *diam.Message, e *diam.MessageError) error {
	a, err := base.BuildErrorAnswer(msg, h.baseSettings(c), e.ResultCode, []*diam.AVP{e.FailedAVP}, false)
	if err != nil {
		return err
	}
	_, err = a.WriteTo(c)
	return err
}
func reviewPeerServer(t *testing.T, wrap bool) (*Manager, net.Conn) {
	t.Helper()
	m, err := New(Config{Settings: testSettings("local.example.net")})
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
	srv := &diam.Server{Dict: dict.Default, MaxConcurrentHandlers: -1}
	if err = m.BindServer(srv); err != nil {
		t.Fatal(err)
	}
	if wrap {
		srv.Handler = consumingErrorHandler{m}
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { closeManager(t, m, srv) })
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return m, c
}
func reviewCER(t *testing.T) *diam.Message {
	t.Helper()
	m, e := base.BuildCER(dict.Default, testBase("known.example.net"))
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func reviewDWR(t *testing.T) *diam.Message {
	t.Helper()
	m, e := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestConsumedMessageErrorDoesNotStallManager(t *testing.T) {
	_, c := reviewPeerServer(t, true)
	write(t, c, reviewCER(t))
	if a := read(t, c); code(t, a) != diam.Success {
		t.Fatal(a)
	}
	bad := reviewDWR(t)
	bad.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	write(t, c, bad)
	if a := read(t, c); code(t, a) != diam.InvalidAVPLength {
		t.Fatal(a)
	}
	next := reviewDWR(t)
	write(t, c, next)
	a := read(t, c)
	if code(t, a) != diam.Success || a.Header.HopByHopID != next.Header.HopByHopID {
		t.Fatal(a)
	}
}
func TestPeerBaseHeaderApplicationOnWire(t *testing.T) {
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(fmt.Sprint(cmd), func(t *testing.T) {
			manager, c := reviewPeerServer(t, false)
			req := reviewCER(t)
			if cmd != diam.CapabilitiesExchange {
				write(t, c, req)
				if a := read(t, c); code(t, a) != diam.Success {
					t.Fatal(a)
				}
				req = reviewDWR(t)
				req.Header.CommandCode = cmd
			}
			req.Header.ApplicationID = 4
			write(t, c, req)
			a := read(t, c)
			if code(t, a) != diam.InvalidHDRBits || a.Header.CommandFlags&diam.ErrorFlag == 0 || a.Header.ApplicationID != 0 {
				t.Fatalf("answer=%v", a)
			}
			if cmd == diam.CapabilitiesExchange {
				if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				_, err := c.Read(make([]byte, 1))
				var ne net.Error
				if err == nil || errors.As(err, &ne) && ne.Timeout() {
					t.Fatalf("CER connection not closed: %v", err)
				}
				return
			}
			select {
			case <-manager.ErrorReports():
			case <-time.After(time.Second):
				t.Fatal("invalid request not reported")
			}
			req.Header.CommandFlags = 0
			req.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
			write(t, c, req)
			next := reviewDWR(t)
			write(t, c, next)
			a = read(t, c)
			if code(t, a) != diam.Success || a.Header.HopByHopID != next.Header.HopByHopID {
				t.Fatalf("invalid answer produced a reply: %v", a)
			}
			for {
				select {
				case report := <-manager.ErrorReports():
					if report.Message.Header.CommandFlags&diam.RequestFlag != 0 {
						continue
					}
					var me *diam.MessageError
					if !errors.As(report.Error, &me) || me.ResultCode != diam.InvalidHDRBits {
						t.Fatalf("invalid answer report: %v", report.Error)
					}
				case <-time.After(time.Second):
					t.Fatal("invalid answer not reported")
				}
				break
			}

		})
	}
}
func TestPeerCERMissingIdentityOnWire(t *testing.T) {
	for _, missing := range []uint32{avp.OriginHost, avp.OriginRealm} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			_, c := reviewPeerServer(t, false)
			req := reviewCER(t)
			for i, a := range req.AVP {
				if a.Code == missing {
					req.AVP = append(req.AVP[:i], req.AVP[i+1:]...)
					break
				}
			}
			write(t, c, req)
			a := read(t, c)
			if code(t, a) != diam.MissingAVP {
				t.Fatal(a)
			}
			f, e := a.FindAVP(avp.FailedAVP, 0)
			if e != nil || f.Data.(*diam.GroupedAVP).AVP[0].Code != missing {
				t.Fatalf("Failed-AVP=%v %v", f, e)
			}
		})
	}
}

// Exercise the session writer and observe close from the other end of the pipe.
type reviewWireConn struct{ *fakeConn }

func (c *reviewWireConn) Write(b []byte) (int, error)               { return c.underlying.Write(b) }
func (c *reviewWireConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }
func (c *reviewWireConn) Close()                                    { c.once.Do(func() { close(c.done); _ = c.underlying.Close() }) }
func TestWaitReturnsMalformedAnsweringConnection(t *testing.T) {
	testWaitReturnsAnsweringConnection(t, true)
}
func TestWaitReturnsValidAnsweringConnection(t *testing.T) {
	testWaitReturnsAnsweringConnection(t, false)
}
func testWaitReturnsAnsweringConnection(t *testing.T, malformed bool) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	c := &reviewWireConn{newFakeConn()}
	defer c.Close()
	defer func() { _ = c.other.Close() }()
	s := &session{m: m, c: c, gen: 1, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	defer s.close()
	m.wg.Add(1)
	go s.writer()
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: WaitReturns, r: s, events: make(chan event, 8)}
	if err = c.other.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var me *diam.MessageError
	if malformed {
		me = &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2})}
	}
	a.onWire(event{kind: wireEvent, s: s, msg: reviewDWR(t), messageErr: me})
	answer, err := diam.ReadMessage(c.other, dict.Default)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected close without a pre-CEA answer: answer=%v err=%v", answer, err)
	}
}
func TestMalformedCEADecodeErrorPreventsAdmission(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	c := newFakeConn()
	defer c.Close()
	req := reviewCER(t)
	s := &session{m: m, c: c, gen: 1, cerHop: req.Header.HopByHopID, cerEnd: req.Header.EndToEndID, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
	a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: WaitICEA, i: s, events: make(chan event, 8)}
	cea, err := base.BuildCEA(req, testBase("known.example.net"), diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	// A valid decoded CEA with a framing error: only messageErr excludes it.
	a.onWire(event{kind: wireEvent, s: s, msg: cea, messageErr: &diam.MessageError{ResultCode: diam.InvalidMessageLength}})
	select {
	case <-s.closed:
	default:
		t.Fatal("CEA with decoder error admitted")
	}
}
func TestClosedSessionErrorIsNotQueueFull(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	c := newFakeConn()
	s := &session{m: m, c: c, closed: make(chan struct{}), writes: make(chan writeRequest, 8), ingress: make(chan incoming, 8)}
	m.sessions[c] = s
	s.close()
	defer m.unregister(s)
	err = m.HandleMessageError(c, reviewDWR(t), &diam.MessageError{ResultCode: diam.InvalidHDRBits})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed ingress error=%v", err)
	}
	if err = m.answerMessageError(s, reviewDWR(t), &diam.MessageError{ResultCode: diam.InvalidHDRBits}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed write error=%v", err)
	}
}

func TestPeerInvalidCERAfterHandshakeCloses(t *testing.T) {
	_, c := reviewPeerServer(t, false)
	write(t, c, reviewCER(t))
	read(t, c)
	req := reviewCER(t)
	req.Header.ApplicationID = 4
	write(t, c, req)
	a := read(t, c)
	if code(t, a) != diam.InvalidHDRBits {
		t.Fatal(a)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("invalid CER did not close: %v", err)
	}
}
