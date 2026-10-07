package sm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func TestCERSecurityValuesOnWire(t *testing.T) {
	for _, secured := range []bool{false, true} {
		for _, values := range [][]uint32{nil, {0}, {1}, {7}, {7, 0}, {7, 1}} {
			t.Run(fmt.Sprintf("TLS=%v/values=%v", secured, values), func(t *testing.T) {
				srv := diamtest.NewUnstartedServer(mustNewStateMachine(t, serverSettings), dict.Default)
				if secured {
					srv.StartTLS()
				} else {
					srv.Start()
				}
				defer srv.Close()
				var c net.Conn
				var err error
				if secured {
					c, err = tls.Dial("tcp", srv.Addr, &tls.Config{InsecureSkipVerify: true})
				} else {
					c, err = net.Dial("tcp", srv.Addr)
				} // #nosec G402 -- local test certificate
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				req := regressionCER(t, dict.Default, 1001)
				common := len(values) == 0
				for _, v := range values {
					req.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(v)))
					common = common || v == 0 || v == 1 && secured
				}
				if _, err = req.WriteTo(c); err != nil {
					t.Fatal(err)
				}
				answer, err := diam.ReadMessage(c, dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				want := uint32(diam.NoCommonSecurity)
				if common {
					want = diam.Success
				}
				if !testResultCode(answer, want) {
					t.Fatalf("CEA = %v, want %d", answer, want)
				}
				if !common {
					regressionClosed(t, c)
				}
			})
		}
	}
}

func TestCERApplicationIntersectionOnWire(t *testing.T) {
	for _, id := range []uint32{0, 999999, 1001, 0xffffffff} {
		for _, grouped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/grouped=%v", id, grouped), func(t *testing.T) {
				settings := *serverSettings
				settings.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
				srv := diamtest.NewServer(mustNewStateMachine(t, &settings), dict.Default)
				defer srv.Close()
				req := regressionCER(t, dict.Default, id)
				if grouped {
					for i, a := range req.AVP {
						if a.Code == avp.AcctApplicationID {
							req.AVP[i] = diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)), a}})
						}
					}
				}
				answer, c := regressionExchange(t, srv, req, dict.Default)
				want := uint32(diam.NoCommonApplication)
				if id == 1001 || id == 0xffffffff {
					want = diam.Success
				}
				if !testResultCode(answer, want) {
					t.Fatalf("CEA = %v, want %d", answer, want)
				}
				if want != diam.Success {
					regressionClosed(t, c)
				}
			})
		}
	}
}

func TestClientRejectsNonCEAOnWire(t *testing.T) {
	for _, kind := range []string{"CER", "DWR", "DWA", "application", "malformed-DWR", "wrong-app-CEA"} {
		t.Run(kind, func(t *testing.T) {
			observed := make(chan error, 1)
			srv := diamtest.NewServer(diam.HandlerFunc(func(c diam.Conn, cer *diam.Message) {
				var msg *diam.Message
				switch kind {
				case "CER":
					msg = regressionCER(t, dict.Default, 1001)
				case "DWR", "malformed-DWR":
					msg = regressionDWR(t)
				case "DWA":
					msg = regressionDWR(t).Answer(diam.Success)
				case "application":
					msg = diam.NewRequest(999999, 1001, dict.Default)
				case "wrong-app-CEA":
					msg = cer.Answer(diam.Success)
					msg.Header.ApplicationID = 1001
				}
				if kind == "malformed-DWR" {
					msg.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
				}
				if _, err := msg.WriteTo(c); err != nil {
					observed <- err
					return
				}
				if err := c.Connection().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					observed <- err
					return
				}
				var b [1]byte
				n, err := c.Connection().Read(b[:])
				var timeout net.Error
				if n != 0 || err == nil || errors.As(err, &timeout) && timeout.Timeout() {
					observed <- errors.Join(fmt.Errorf("client did not close without answering: n=%d", n), err)
					return
				}
				observed <- nil
			}), dict.Default)
			defer srv.Close()
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.RetransmitInterval = 2 * time.Second
			c, err := cli.Dial(srv.Addr)
			if c != nil {
				c.Close()
			}
			if err == nil || errors.Is(err, ErrHandshakeTimeout) {
				t.Errorf("Dial = %v, want immediate non-CEA error", err)
			}
			if err := <-observed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCEAErrorsPreserveCause(t *testing.T) {
	c := newErrWriteConn()
	settings := *serverSettings
	settings.HostIPAddresses = []datatype.Address{localhostAddress}
	sm := mustNewStateMachine(t, &settings)
	err := errorCEA(sm, c, regressionCER(t, dict.Default, 1001), smparser.ErrNoCommonApplication)
	if !errors.Is(err, c.writeErr) || !errors.Is(err, smparser.ErrNoCommonApplication) {
		t.Fatalf("errorCEA lost write cause: %v", err)
	}
}

func TestLivenessHandshakeNotificationsDoNotLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	t.Run("clean-EOF", TestCleanEOFWakesSupervisor)
	t.Run("already-closed", TestCloseNotifyAfterPeerGone)
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if after := runtime.NumGoroutine(); after > before {
		stacks := make([]byte, 1<<20)
		n := runtime.Stack(stacks, true)
		t.Fatalf("goroutines before=%d after=%d\n%s", before, after, stacks[:n])
	}
}

type emptyLocalAddr struct{}

func (emptyLocalAddr) Network() string { return "test" }
func (emptyLocalAddr) String() string  { return "" }

type invalidLocalConn struct{ *errWriteConn }

func (*invalidLocalConn) LocalAddr() net.Addr { return emptyLocalAddr{} }

func TestCapabilityAddressErrorsPreserveCause(t *testing.T) {
	settings := *serverSettings
	settings.HostIPAddresses = nil
	sm := mustNewStateMachine(t, &settings)
	c := &invalidLocalConn{newErrWriteConn()}
	request := regressionCER(t, dict.Default, 1001)
	err := errorCEA(sm, c, request, smparser.ErrNoCommonApplication)
	var causes interface{ Unwrap() []error }
	if !errors.Is(err, smparser.ErrNoCommonApplication) || !errors.As(err, &causes) {
		t.Fatalf("error CEA lost capability failure: %v", err)
	}
	foundAddress := false
	for _, cause := range causes.Unwrap() {
		foundAddress = foundAddress || cause.Error() == "empty local address"
	}
	if !foundAddress {
		t.Fatalf("error CEA lost address cause: %v", err)
	}
	cli := &Client{Handler: sm}
	_, err = cli.handshake(c, newWatchdogActivity())
	if cause := errors.Unwrap(err); cause == nil || cause.Error() != "empty local address" {
		t.Fatalf("client lost address cause: %v", err)
	}
}
