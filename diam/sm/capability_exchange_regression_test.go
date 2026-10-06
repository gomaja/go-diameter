package sm

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
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
)

func regressionCER(t *testing.T, dictionary *dict.Parser, app uint32) *diam.Message {
	t.Helper()
	m := diam.NewRequest(diam.CapabilitiesExchange, 0, dictionary)
	for _, field := range []struct {
		code  uint32
		flags uint8
		data  datatype.Type
	}{
		{avp.OriginHost, avp.Mbit, clientSettings.OriginHost},
		{avp.OriginRealm, avp.Mbit, clientSettings.OriginRealm},
		{avp.HostIPAddress, avp.Mbit, localhostAddress},
		{avp.VendorID, avp.Mbit, clientSettings.VendorID},
		{avp.ProductName, 0, clientSettings.ProductName},
		{avp.AcctApplicationID, avp.Mbit, datatype.Unsigned32(app)},
	} {
		if _, err := m.NewAVP(field.code, field.flags, 0, field.data); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func regressionExchange(t *testing.T, server *diamtest.Server, request *diam.Message, dictionary *dict.Parser) (*diam.Message, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err = request.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(c, dictionary)
	if err != nil {
		t.Fatal(err)
	}
	return answer, c
}

func regressionClosed(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	var timeout net.Error
	if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("connection stayed open: %v", err)
	}
}

func TestAcceptedConnectionRejectsMessagesBeforeCER(t *testing.T) {
	for _, command := range []uint32{diam.DeviceWatchdog, 0xfedc} {
		t.Run(fmt.Sprint(command), func(t *testing.T) {
			srv := diamtest.NewServer(New(testMessageErrorSettings()), dict.Default)
			defer srv.Close()
			c, err := net.DialTimeout("tcp", srv.Addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			request := diam.NewRequest(command, 0, dict.Default)
			mustSMClientAVP(t, request, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
			mustSMClientAVP(t, request, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
			if _, err = request.WriteTo(c); err != nil {
				t.Fatal(err)
			}
			regressionClosed(t, c)
		})
	}
}

func TestCERAcceptsAnyCommonSecurityValue(t *testing.T) {
	for _, values := range [][]uint32{nil, {0}, {0, 1}, {1, 0}, {1}, {2}} {
		t.Run(fmt.Sprint(values), func(t *testing.T) {
			srv := diamtest.NewServer(New(serverSettings), dict.Default)
			defer srv.Close()
			request := regressionCER(t, dict.Default, 1001)
			for _, v := range values {
				if _, err := request.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(v)); err != nil {
					t.Fatal(err)
				}
			}
			answer, c := regressionExchange(t, srv, request, dict.Default)
			want := uint32(diam.Success)
			if len(values) == 1 && values[0] != 0 {
				want = diam.NoCommonSecurity
			}
			if !testResultCode(answer, want) {
				result, _ := answer.FindAVP(avp.ResultCode, 0)
				t.Fatalf("values %v: Result-Code = %v, want %d", values, result.Data, want)
			}
			if want == diam.NoCommonSecurity {
				regressionClosed(t, c)
			}
		})
	}
}

func TestCERMalformedInbandSecurityReturnsFailedAVP(t *testing.T) {
	dictionary, err := dict.NewParser("../dict/testdata/base.xml", "../dict/testdata/credit_control.xml")
	if err != nil {
		t.Fatal(err)
	}
	dictionary.Strict = false
	settings := *serverSettings
	observed := make(chan uint32, 2)
	settings.OnCEA = func(_ diam.Conn, answer *diam.Message) {
		if code, err := answer.FindAVP(avp.ResultCode, 0); err == nil {
			observed <- uint32(code.Data.(datatype.Unsigned32))
		}
	}
	srv := diamtest.NewServer(New(&settings), dictionary)
	defer srv.Close()
	request := regressionCER(t, dictionary, 1001)
	wire, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 12)
	binary.BigEndian.PutUint32(raw[:4], avp.InbandSecurityID)
	raw[4] = avp.Mbit
	raw[7] = 10
	raw[8] = 0
	raw[9] = 1
	wire = append(wire, raw...)
	binary.BigEndian.PutUint32(wire[:4], uint32(len(wire)))
	wire[0] = 1
	c, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err = c.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(c, dictionary)
	if err != nil {
		t.Fatalf("read CEA: %v", err)
	}
	if !testResultCode(answer, diam.InvalidAVPLength) {
		t.Fatalf("CEA = %v, want 5014", answer)
	}
	failed, err := answer.FindAVP(avp.FailedAVP, 0)
	if err != nil {
		t.Fatalf("missing Failed-AVP: %v", err)
	}
	// The non-Strict dictionary preserves the malformed child as raw wire
	// bytes; the single Failed-AVP must contain exactly that child.
	data, ok := failed.Data.(datatype.Unknown)
	if !ok || !bytes.Equal(data, raw) {
		t.Fatalf("Failed-AVP = %v", failed)
	}
	count := 0
	for _, a := range answer.AVP {
		if a.Code == avp.FailedAVP {
			count++
		}
	}
	if count != 1 || answer.Header.CommandFlags != 0 {
		t.Fatalf("Failed-AVP count=%d, flags=%#x", count, answer.Header.CommandFlags)
	}
	select {
	case code := <-observed:
		if code != diam.InvalidAVPLength {
			t.Fatalf("OnCEA result=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("OnCEA not called")
	}
	regressionClosed(t, c)
}

func TestCERUsesSettingsDictionaryForApplications(t *testing.T) {
	narrow, err := dict.NewParser("../dict/testdata/base.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err = narrow.Load(bytes.NewReader([]byte(acctDictionary))); err != nil {
		t.Fatal(err)
	}
	settings := *serverSettings
	settings.Dict = narrow
	srv := diamtest.NewServer(New(&settings), dict.Default)
	defer srv.Close()
	request := regressionCER(t, dict.Default, 1001)
	for _, a := range request.AVP {
		if a.Code == avp.AcctApplicationID {
			a.Code = avp.AuthApplicationID
			a.Data = datatype.Unsigned32(4)
		}
	}
	answer, _ := regressionExchange(t, srv, request, dict.Default)
	if !testResultCode(answer, diam.NoCommonApplication) {
		result, _ := answer.FindAVP(avp.ResultCode, 0)
		t.Fatalf("Result-Code = %v, want 5010", result.Data)
	}
}

func TestClientRefusesInbandTLSOnPlaintext(t *testing.T) {
	testClientRefusesInbandTLSOnPlaintext(t, "tcp")
}

func testClientRefusesInbandTLSOnPlaintext(t *testing.T, network string) {
	t.Helper()
	seen := make(chan struct{}, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		seen <- struct{}{}
		answer := m.Answer(diam.Success)
		for _, field := range []struct {
			code  uint32
			flags uint8
			data  datatype.Type
		}{
			{avp.OriginHost, avp.Mbit, serverSettings.OriginHost},
			{avp.OriginRealm, avp.Mbit, serverSettings.OriginRealm},
			{avp.HostIPAddress, avp.Mbit, localhostAddress},
			{avp.VendorID, avp.Mbit, serverSettings.VendorID},
			{avp.ProductName, 0, serverSettings.ProductName},
			{avp.AcctApplicationID, avp.Mbit, datatype.Unsigned32(3)},
		} {
			if _, err := answer.NewAVP(field.code, field.flags, 0, field.data); err != nil {
				return
			}
		}
		_, _ = answer.WriteTo(c)
	})
	opened := make(chan diam.Conn, 1)
	srv := diamtest.NewUnstartedServerNetwork(network, mux, dict.Default)
	srv.Config.OnNewConnection = func(c diam.Conn) { opened <- c }
	srv.Start()
	defer srv.Close()
	cli := &Client{Handler: New(clientSettings), InbandSecurityID: 1, RetransmitInterval: 100 * time.Millisecond,
		AcctApplicationID: []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))}}
	c, err := cli.DialNetwork(network, srv.Addr)
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("Dial = %v, want TLS requirement", err)
	}
	var peer diam.Conn
	select {
	case peer = <-opened:
	case <-time.After(time.Second):
		t.Fatal("server did not accept dial")
	}
	select {
	case <-peer.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
	case <-time.After(time.Second):
		t.Fatal("rejected connection did not close")
	}
	select {
	case <-seen:
		t.Fatal("CER sent before rejecting plaintext TLS offer")
	default:
	}
}

func TestHandshakeTimeoutClosesSilentAcceptedConnections(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(useTLS), func(t *testing.T) {
			settings := *serverSettings
			settings.HandshakeTimeout = 150 * time.Millisecond
			srv := diamtest.NewUnstartedServer(New(&settings), dict.Default)
			if useTLS {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			var c net.Conn
			var err error
			if useTLS {
				c, err = tls.Dial("tcp", srv.Addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test certificate
			} else {
				c, err = net.DialTimeout("tcp", srv.Addr, time.Second)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			regressionClosed(t, c)
		})
	}
}

func TestHandshakeTimeoutStopsAfterCER(t *testing.T) {
	settings := *serverSettings
	settings.HandshakeTimeout = 100 * time.Millisecond
	srv := diamtest.NewServer(New(&settings), dict.Default)
	defer srv.Close()
	answer, c := regressionExchange(t, srv, regressionCER(t, dict.Default, 1001), dict.Default)
	if !testResultCode(answer, diam.Success) {
		t.Fatalf("CEA = %v", answer)
	}
	<-time.After(3 * settings.HandshakeTimeout)
	request := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	for _, field := range []struct {
		code uint32
		data datatype.Type
	}{{avp.OriginHost, clientSettings.OriginHost}, {avp.OriginRealm, clientSettings.OriginRealm}} {
		if _, err := request.NewAVP(field.code, avp.Mbit, 0, field.data); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := request.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	dwa, err := diam.ReadMessage(c, dict.Default)
	if err != nil {
		t.Fatalf("read DWA after timeout: %v", err)
	}
	if dwa.Header.CommandCode != diam.DeviceWatchdog || !testResultCode(dwa, diam.Success) {
		t.Fatalf("DWA = %v", dwa)
	}
}

func TestNegativeHandshakeTimeoutLeavesSilentConnectionOpen(t *testing.T) {
	settings := *serverSettings
	settings.HandshakeTimeout = -1
	srv := diamtest.NewServer(New(&settings), dict.Default)
	defer srv.Close()
	c, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read = %v, want open connection", err)
	}
}

func TestAcceptedConnectionRejectsMalformedNonCERWithoutAnswer(t *testing.T) {
	srv := diamtest.NewServer(New(testMessageErrorSettings()), dict.Default)
	defer srv.Close()
	c, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	request := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	wire, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	malformed := make([]byte, 8)
	binary.BigEndian.PutUint32(malformed[:4], avp.InbandSecurityID)
	malformed[4] = avp.Mbit
	malformed[7] = 4
	wire = append(wire, malformed...)
	binary.BigEndian.PutUint32(wire[:4], uint32(len(wire)))
	wire[0] = 1
	if _, err = c.Write(wire); err != nil {
		t.Fatal(err)
	}
	regressionClosed(t, c)
}
