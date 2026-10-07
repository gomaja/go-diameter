package sm

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func TestServerApplicationLookupSnapshot(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			cfg := testMessageErrorSettings()
			if explicit {
				cfg.Dict = dict.Default
			}
			sm := mustNewStateMachine(t, cfg)
			c := newHandshakeConn()
			sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
			<-c.writes
			if !sm.supportsApplicationOn(c, 1001) {
				t.Fatal("advertised app unsupported")
			}
			if n := testing.AllocsPerRun(100, func() { sm.supportsApplicationOn(c, 1001) }); n != 0 {
				t.Fatalf("lookup allocated %g times; want zero", n)
			}
		})
	}
}
func BenchmarkSupportsApplicationOn(b *testing.B) {
	for _, explicit := range []bool{false, true} {
		b.Run(fmt.Sprint(explicit), func(b *testing.B) {
			cfg := testMessageErrorSettings()
			if explicit {
				cfg.Dict = dict.Default
			}
			sm, err := New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			c := newHandshakeConn()
			req := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
			req.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("remote.example")))
			req.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			req.AddAVP(diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001)))
			sm.ServeDIAM(c, req)
			<-c.writes
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				sm.supportsApplicationOn(c, 1001)
			}
		})
	}
}

type nilDictionaryConn struct{ *handshakeConn }

func (*nilDictionaryConn) Dictionary() *dict.Parser { return nil }
func TestCERNilConnectionDictionary(t *testing.T) {
	cfg := testMessageErrorSettings()
	cfg.Dict = nil
	sm := mustNewStateMachine(t, cfg)
	private := dict.New(dict.Base)
	if err := private.Load(strings.NewReader(`<diameter><application id="16777999" name="Private" type="auth"/></diameter>`)); err != nil {
		t.Fatal(err)
	}
	for _, dp := range []*dict.Parser{nil, private} {
		c := &nilDictionaryConn{newHandshakeConn()}
		app := uint32(4)
		if dp != nil {
			app = 16777999
		}
		req := regressionCER(t, dp, app)
		sm.ServeDIAM(c, req)
		answer, err := diam.ReadMessage(bytes.NewReader(<-c.writes), dict.Default)
		if err != nil || !testResultCode(answer, diam.Success) {
			t.Fatalf("answer=%v err=%v", answer, err)
		}
	}
}
func TestWrappedCEAResultCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want uint32
	}{{smparser.ErrNoCommonSecurity, diam.NoCommonSecurity}, {smparser.ErrNoCommonApplication, diam.NoCommonApplication}} {
		sm := mustNewStateMachine(t, testMessageErrorSettings())
		c := newHandshakeConn()
		if err := errorCEA(sm, c, regressionCER(t, dict.Default, 1001), fmt.Errorf("wrapped: %w", tc.err)); err != nil {
			t.Fatal(err)
		}
		a, err := diam.ReadMessage(bytes.NewReader(<-c.writes), dict.Default)
		if err != nil || !testResultCode(a, tc.want) {
			t.Fatalf("answer=%v err=%v want=%d", a, err, tc.want)
		}
	}
}
func TestSettingsRejectApplicationZero(t *testing.T) {
	for _, kind := range []uint32{avp.AuthApplicationID, avp.AcctApplicationID} {
		for _, grouped := range []bool{false, true} {
			cfg := testMessageErrorSettings()
			a := diam.NewAVP(kind, avp.Mbit, 0, datatype.Unsigned32(0))
			if grouped {
				cfg.VendorSpecificApplicationID = []*diam.AVP{diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)), a}})}
			} else if kind == avp.AuthApplicationID {
				cfg.AuthApplicationID = []*diam.AVP{a}
			} else {
				cfg.AcctApplicationID = []*diam.AVP{a}
			}
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "application 0") {
				t.Errorf("kind=%d grouped=%t: %v", kind, grouped, err)
			}
		}
	}
}
func TestCERMissingIdentityOnWire(t *testing.T) {
	for _, missing := range []uint32{avp.OriginHost, avp.OriginRealm} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			srv := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), dict.Default)
			defer srv.Close()
			req := regressionCER(t, dict.Default, 1001)
			for i, a := range req.AVP {
				if a.Code == missing {
					req.AVP = append(req.AVP[:i], req.AVP[i+1:]...)
					break
				}
			}
			a, c := regressionExchange(t, srv, req, dict.Default)
			if !testResultCode(a, diam.MissingAVP) {
				t.Fatalf("answer=%v", a)
			}
			var count int
			for _, v := range a.AVP {
				if v.Code == avp.FailedAVP {
					count++
					g, ok := v.Data.(*diam.GroupedAVP)
					if !ok || len(g.AVP) != 1 || g.AVP[0].Code != missing {
						t.Fatalf("Failed-AVP=%v", v)
					}
				}
			}
			if count != 1 {
				t.Fatalf("Failed-AVP count=%d", count)
			}
			regressionClosed(t, c)
		})
	}
}
func TestSharedStateMachineStillAnswersCER(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	remote := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), dict.Default)
	defer remote.Close()
	for i := 0; i < 3; i++ {
		a, _ := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
		if !testResultCode(a, diam.Success) {
			t.Fatalf("inbound %d: %v", i, a)
		}
		if i < 2 {
			cli := &Client{Handler: sm}
			c, err := cli.Dial(remote.Addr)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	}
}
func TestLateNonCEAAfterHandshakeTimeout(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	cli := &Client{Handler: sm, RetransmitInterval: time.Nanosecond}
	activity := newWatchdogActivity()
	activity.capabilities = cli.capabilitySettings(nil)
	c := newHandshakeConn()
	if _, err := cli.handshake(c, activity); err != ErrHandshakeTimeout {
		t.Fatalf("handshake: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		activityHandler{StateMachine: sm, activity: activity}.ServeDIAM(c, regressionDWR(t))
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("late non-CEA blocked reader")
		<-activity.ceac
		<-done
	}
}

func TestSMBaseHeaderApplicationOnWire(t *testing.T) {
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		t.Run(fmt.Sprint(cmd), func(t *testing.T) {
			records := logtest.New()
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			srv := diamtest.NewUnstartedServer(sm, dict.Default)
			srv.Config.Logger = records.Logger()
			srv.Start()
			defer srv.Close()
			if cmd == diam.CapabilitiesExchange {
				req := regressionCER(t, dict.Default, 1001)
				req.Header.ApplicationID = 4
				a, c := regressionExchange(t, srv, req, dict.Default)
				if !testResultCode(a, diam.InvalidHDRBits) || a.Header.CommandFlags&diam.ErrorFlag == 0 || a.Header.ApplicationID != 0 {
					t.Fatalf("invalid CER answer=%v", a)
				}
				regressionClosed(t, c)
				return
			}
			_, c := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
			for _, request := range []bool{true, false} {
				req := regressionDWR(t)
				req.Header.CommandCode = cmd
				req.Header.ApplicationID = 4
				if !request {
					req.Header.CommandFlags = 0
					req.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
				}
				if _, err := req.WriteTo(c); err != nil {
					t.Fatal(err)
				}
				if request {
					a, err := diam.ReadMessage(c, dict.Default)
					if err != nil || !testResultCode(a, diam.InvalidHDRBits) || a.Header.CommandFlags&diam.ErrorFlag == 0 || a.Header.ApplicationID != 0 {
						t.Fatalf("invalid base request answer=%v err=%v", a, err)
					}
					_ = waitLog(t, records, 1)
				} else {
					record := waitLog(t, records, 2)
					var me *diam.MessageError
					if !errors.As(logError(record), &me) || me.ResultCode != diam.InvalidHDRBits {
						t.Fatalf("invalid answer record: %v", record)
					}

				}
			}
			next := regressionDWR(t)
			if _, err := next.WriteTo(c); err != nil {
				t.Fatal(err)
			}
			a, err := diam.ReadMessage(c, dict.Default)
			if err != nil || !testResultCode(a, diam.Success) || a.Header.HopByHopID != next.Header.HopByHopID {
				t.Fatalf("invalid answer produced reply or closed connection: %v %v", a, err)
			}
		})
	}
}

type gatedSMHandler struct {
	*StateMachine
	started, release, errored chan struct{}
}

func (h *gatedSMHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == diam.CapabilitiesExchange {
		close(h.started)
		<-h.release
	}
	h.StateMachine.ServeDIAM(c, m)
}
func (h *gatedSMHandler) HandleMessageError(c diam.Conn, m *diam.Message, e *diam.MessageError) error {
	close(h.errored)
	return h.StateMachine.HandleMessageError(c, m, e)
}
func TestSMConcurrentCERThenMalformedOnWire(t *testing.T) {
	h := &gatedSMHandler{StateMachine: mustNewStateMachine(t, testMessageErrorSettings()), started: make(chan struct{}), release: make(chan struct{}), errored: make(chan struct{})}
	srv := diamtest.NewUnstartedServer(h, dict.Default)
	srv.Config.MaxConcurrentHandlers = -1
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
	req := regressionCER(t, dict.Default, 1001)
	if _, err = req.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	<-h.started
	malformed := regressionDWR(t)
	malformed.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	if _, err = malformed.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	<-h.errored
	close(h.release)
	for _, want := range []uint32{diam.Success, diam.InvalidAVPLength} {
		a, e := diam.ReadMessage(c, dict.Default)
		if e != nil || !testResultCode(a, want) {
			t.Fatalf("want %d, answer=%v err=%v", want, a, e)
		}
		if want == diam.InvalidAVPLength {
			f, e := a.FindAVP(avp.FailedAVP, 0)
			if e != nil || f == nil {
				t.Fatal("missing Failed-AVP")
			}
		}
	}
}

func TestSMInvalidCERAfterHandshakeCloses(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), dict.Default)
	defer srv.Close()
	_, c := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
	req := regressionCER(t, dict.Default, 1001)
	req.Header.ApplicationID = 4
	if _, err := req.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	a, err := diam.ReadMessage(c, dict.Default)
	if err != nil || !testResultCode(a, diam.InvalidHDRBits) {
		t.Fatalf("answer=%v %v", a, err)
	}
	regressionClosed(t, c)
}
