package sm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestUnsupportedCommandAnswerTCP(t *testing.T) {
	for _, command := range []uint32{0xfedc, diam.ReAuth} {
		t.Run(fmt.Sprint(command), func(t *testing.T) {
			testUnsupportedCommandAnswerTCP(t, command, 0, diam.CommandUnsupported)
		})
	}
}

// TestUnsupportedApplicationAnswerTCP checks RFC 6733 §7.1.3: 3007 for an
// application this node does not advertise, 3001 for an unknown command in
// one it does.
func TestUnsupportedApplicationAnswerTCP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		appID uint32
		want  uint32
	}{
		{"unknown application", 0x00abcdef, diam.ApplicationUnsupported},
		{"unknown command in a supported application", diam.CHARGING_CONTROL_APP_ID, diam.CommandUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) { testUnsupportedCommandAnswerTCP(t, 0xfedc, tc.appID, tc.want) })
	}
}

// RFC 6733 §§5.3, 5.6: application support on a connection follows the
// local CER offer, including an explicit ID absent from the dictionary.
func TestClientOverrideControlsConnectionApplications(t *testing.T) {
	for _, validateRequests := range []bool{false, true} {
		t.Run(fmt.Sprintf("ValidateRequests=%t", validateRequests), func(t *testing.T) {
			testClientOverrideControlsConnectionApplications(t, validateRequests)
		})
	}
}

func testClientOverrideControlsConnectionApplications(t *testing.T, validateRequests bool) {
	t.Helper()
	const customApp = 16777999
	application := diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(customApp))
	serverCfg := *serverSettings
	serverCfg.AuthApplicationID = []*diam.AVP{application}
	serverCfg.ValidateRequests = validateRequests
	serverSM := mustNew(&serverCfg)
	serverAnswers := capabilityAnswerHandler(serverSM)
	server := diamtest.NewServer(serverSM, dict.Default)
	defer server.Close()
	clientCfg := *clientSettings
	clientCfg.ValidateRequests = validateRequests
	clientSM := mustNew(&clientCfg)
	clientAnswers := capabilityAnswerHandler(clientSM)
	client := &Client{Handler: clientSM, AuthApplicationID: []*diam.AVP{application}}
	conn, err := client.Dial(server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !clientSM.supportsApplicationOn(conn, customApp) || clientSM.supportsApplicationOn(conn, 4) {
		t.Fatal("client connection applications differ from the explicit CER offer")
	}
	var serverConn diam.Conn
	select {
	case serverConn = <-serverSM.HandshakeNotify():
	case <-time.After(time.Second):
		t.Fatal("server handshake notification timed out")
	}
	for _, tc := range []struct {
		app, result uint32
	}{{customApp, diam.CommandUnsupported}, {4, diam.ApplicationUnsupported}} {
		request := diam.NewMessage(0xfedc, diam.RequestFlag, tc.app, 3, 4, dict.Default)
		if _, err := request.WriteTo(serverConn); err != nil {
			t.Fatal(err)
		}
		awaitCapabilityAnswer(t, serverAnswers, request, tc.result)
	}
	for _, tc := range []struct {
		app, result uint32
	}{{customApp, diam.CommandUnsupported}, {4, diam.ApplicationUnsupported}} {
		request := diam.NewMessage(0xfedc, diam.RequestFlag, tc.app, 1, 2, dict.Default)
		if _, err := request.WriteTo(conn); err != nil {
			t.Fatal(err)
		}
		awaitCapabilityAnswer(t, clientAnswers, request, tc.result)
	}
}

func capabilityAnswerHandler(sm *StateMachine) <-chan *diam.Message {
	// ErrorReports is a lossy diagnostic channel: an earlier unhandled
	// request can fill its buffer and cause the answer report to be dropped.
	// Register before connecting and collect answers independently. There is
	// only one outstanding request per direction, so one buffered slot suffices.
	answers := make(chan *diam.Message, 1)
	sm.HandleFunc("ALL", func(c diam.Conn, m *diam.Message) {
		if m.Header.CommandFlags&diam.RequestFlag != 0 {
			// Keep exercising the production unsupported-command fallback.
			sm.handleUnsupportedCommand(c, m)
			return
		}
		answers <- m
	})
	return answers
}

func awaitCapabilityAnswer(t *testing.T, answers <-chan *diam.Message, request *diam.Message, result uint32) {
	t.Helper()
	select {
	case answer := <-answers:
		// RFC 6733 §§6.2 and 7.2: correlate the error answer with its request.
		if answer.Header.ApplicationID != request.Header.ApplicationID ||
			answer.Header.CommandCode != request.Header.CommandCode ||
			answer.Header.HopByHopID != request.Header.HopByHopID ||
			answer.Header.EndToEndID != request.Header.EndToEndID ||
			answer.Header.CommandFlags != diam.ErrorFlag || !testResultCode(answer, result) {
			t.Fatalf("application %d answer = %v; want matching error answer with result %d", request.Header.ApplicationID, answer, result)
		}
	case <-time.After(time.Second):
		t.Fatalf("application %d answer timed out", request.Header.ApplicationID)
	}
}

func testUnsupportedCommandAnswerTCP(t *testing.T, command, appID, want uint32) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	completeUnsupportedTestCER(t, conn)
	request := diam.NewMessage(command, diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag, appID, 0x1234, 0x5678, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
		t.Fatalf("wrong answer header: %+v", answer.Header)
	}
	if answer.Header.CommandFlags != diam.ErrorFlag|diam.ProxiableFlag {
		t.Fatalf("answer flags = %#x", answer.Header.CommandFlags)
	}
	if !testResultCode(answer, want) {
		t.Fatalf("answer result code, want %d: %v", want, answer)
	}
	if got := answer.AVP[0].Data; got != testMessageErrorSettings().OriginHost {
		t.Fatalf("Origin-Host = %v", got)
	}
	if got := answer.AVP[1].Data; got != testMessageErrorSettings().OriginRealm {
		t.Fatalf("Origin-Realm = %v", got)
	}
}

func TestUnsupportedCommandNeverAnswersAnswer(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	completeUnsupportedTestCER(t, conn)
	answer := diam.NewMessage(0xfedc, 0, 0, 0x1234, 0x5678, dict.Default)
	if _, err := answer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("read = %v, want timeout", err)
	}
}

func TestUnsupportedCommandHonorsAllHandler(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	seen := make(chan struct{}, 1)
	sm.HandleFunc("ALL", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	writeValidSMErrorCER(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := diam.ReadMessage(conn, dict.Default); err != nil {
		t.Fatalf("read CEA: %v", err)
	}
	request := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 1, 2, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("ALL handler was not called")
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("read = %v, want timeout", err)
	}
}

// TestUnsupportedCommandStillReported keeps the error report ServeMux sent
// for unhandled messages before the 3001 fallback existed: an unhandled
// request is answered with 3001 and reported, and an unhandled answer is
// reported rather than dropped silently.
func TestUnsupportedCommandStillReported(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	completeUnsupportedTestCER(t, conn)
	waitReport := func(want string) {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			select {
			case r := <-sm.ErrorReports():
				if r.Error != nil && strings.Contains(r.Error.Error(), want) {
					return
				}
			case <-deadline:
				t.Fatalf("no error report containing %q", want)
			}
		}
	}
	request := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 1, 2, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	waitReport("Code:65244 Request:true")
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if answer, err := diam.ReadMessage(conn, dict.Default); err != nil || !testResultCode(answer, diam.CommandUnsupported) {
		t.Fatalf("want 3001 answer, got %v, %v", answer, err)
	}
	answer := diam.NewMessage(0xfedc, 0, 0, 3, 4, dict.Default)
	if _, err := answer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	waitReport("Code:65244 Request:false")
}

func completeUnsupportedTestCER(t *testing.T, conn net.Conn) {
	t.Helper()
	writeValidSMErrorCER(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil || !testResultCode(answer, diam.Success) {
		t.Fatalf("CER answer = %v, %v", answer, err)
	}
}

// TestSupportsApplication covers the base application, an advertised one, an
// unknown one, and the relay application covering all (RFC 6733 §2.4).
func TestSupportsApplication(t *testing.T) {
	sm := mustNewStateMachine(t, testMessageErrorSettings())
	for appID, want := range map[uint32]bool{0: true, diam.CHARGING_CONTROL_APP_ID: true, 0x00abcdef: false} {
		if got := sm.supportsApplication(appID); got != want {
			t.Errorf("supportsApplication(%d) = %t, want %t", appID, got, want)
		}
	}
	relay := dict.New(dict.Base)
	if err := relay.Load(strings.NewReader(`<diameter><application id="4294967295" type="auth" name="Relay"></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	settings := testMessageErrorSettings()
	settings.Dict = relay
	if !mustNewStateMachine(t, settings).supportsApplication(0x00abcdef) {
		t.Error("a relay must support every application")
	}
}

// TestValidateRequestsUsesAdvertisedApplications checks that request
// validation decides 3007 from the applications the state machine
// advertises, not from the dictionary that decoded the message (RFC 6733
// §7.1.3). An unknown command in an advertised application stays 3001.
func TestValidateRequestsUsesAdvertisedApplications(t *testing.T) {
	baseOnly := func(t *testing.T) *dict.Parser {
		t.Helper()
		p := dict.New(dict.Base)
		return p
	}
	relay := func(t *testing.T) *dict.Parser {
		t.Helper()
		p := baseOnly(t)
		if err := p.Load(strings.NewReader(`<diameter><application id="4294967295" type="auth" name="Relay"></application></diameter>`)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name               string
		advertised, onWire func(*testing.T) *dict.Parser
		appID, want        uint32
	}{
		{"advertised, unknown to the decoding dictionary", func(*testing.T) *dict.Parser { return dict.Default }, baseOnly, diam.CHARGING_CONTROL_APP_ID, diam.CommandUnsupported},
		{"relay advertised", relay, baseOnly, 77, diam.CommandUnsupported},
		{"known to the decoding dictionary, not advertised", baseOnly, func(*testing.T) *dict.Parser { return dict.Default }, diam.CHARGING_CONTROL_APP_ID, diam.ApplicationUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.Dict = tc.advertised(t)
			settings.ValidateRequests = true
			wire := tc.onWire(t)
			srv := diamtest.NewServer(mustNewStateMachine(t, settings), wire)
			defer srv.Close()
			conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Base accounting is common to every dictionary here (RFC 6733 §5.3).
			cer := diam.NewRequest(diam.CapabilitiesExchange, 0, wire)
			mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
			mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
			mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1")))
			mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13))
			mustSMClientAVP(t, cer, avp.ProductName, 0, 0, datatype.UTF8String("peer"))
			mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))
			if _, err := cer.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			if cea, err := diam.ReadMessage(conn, wire); err != nil || !testResultCode(cea, diam.Success) {
				t.Fatalf("CEA = %v, %v", cea, err)
			}
			request := diam.NewMessage(0xfedc, diam.RequestFlag|diam.ProxiableFlag, tc.appID, 0x1234, 0x5678, wire)
			if _, err := request.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			answer, err := diam.ReadMessage(conn, wire)
			if err != nil {
				t.Fatal(err)
			}
			if answer.Header.CommandFlags&diam.ErrorFlag == 0 || !testResultCode(answer, tc.want) {
				t.Fatalf("want E-bit %d: %v", tc.want, answer)
			}
		})
	}
}

// TestValidateRequestsClosesCERForUnsupportedApplication checks that a CER
// rejected with 3007 because its header names an application this node does
// not advertise also closes the connection (RFC 6733 §§5.3, 5.6.1).
func TestValidateRequestsClosesCERForUnsupportedApplication(t *testing.T) {
	baseOnly := dict.New(dict.Base)
	settings := testMessageErrorSettings()
	settings.Dict = baseOnly
	settings.ValidateRequests = true
	srv := diamtest.NewServer(mustNewStateMachine(t, settings), dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, diam.CHARGING_CONTROL_APP_ID, 0x1234, 0x5678, dict.Default)
	mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
	mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
	mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1")))
	mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13))
	mustSMClientAVP(t, cer, avp.ProductName, 0, 0, datatype.UTF8String("peer"))
	mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))
	if _, err := cer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Header.CommandFlags&diam.ErrorFlag == 0 || !testResultCode(answer, diam.ApplicationUnsupported) {
		t.Fatalf("want E-bit 3007: %v", answer)
	}
	if extra, err := diam.ReadMessage(conn, dict.Default); err == nil {
		t.Fatalf("connection stayed open after the rejected CER: %v", extra)
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("read after the rejected CER: %v, want EOF", err)
	}
}
