// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/testutil"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-sctp"
)

func mustSMClientAVP(t *testing.T, m *diam.Message, code uint32, flags uint8, vendor uint32, data datatype.Type) {
	t.Helper()
	if _, err := m.NewAVP(code, flags, vendor, data); err != nil {
		t.Fatal(err)
	}
}

func mustWriteSMClientMessage(t *testing.T, m *diam.Message, c diam.Conn) {
	t.Helper()
	if _, err := m.WriteTo(c); err != nil {
		t.Fatal(err)
	}
}

func TestClient_Dial_MissingStateMachine(t *testing.T) {
	cli := &Client{}
	_, err := cli.Dial("")
	if err != ErrMissingStateMachine {
		t.Fatal(err)
	}
}

func TestClient_Dial_InvalidAddress(t *testing.T) {
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0,
				datatype.Unsigned32(0)),
		},
	}
	c, err := cli.Dial(":0")
	if err == nil {
		c.Close()
		t.Fatal("Invalid client address succeeded")
	}
}

func TestClient_DialTLS_InvalidAddress(t *testing.T) {
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(0)),
		},
	}
	c, err := cli.DialTLS(":0", "", "")
	if err == nil {
		c.Close()
		t.Fatal("Invalid client address succeeded")
	}
}

func TestClient_ServerCarriesTLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	cli := &Client{
		Handler:   mustNewStateMachine(t, clientSettings),
		TLSConfig: tlsConfig,
	}

	srv := cli.server("tcp", "example.net:3868", nil, nil)
	if srv.TLSConfig != tlsConfig {
		t.Fatal("client server template did not carry TLSConfig")
	}
}

func TestClient_Handshake(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		SupportedVendorID: []*diam.AVP{
			diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, clientSettings.VendorID),
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
		AuthApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		},
		VendorSpecificApplicationID: []*diam.AVP{
			diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
				},
			}),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestClient_Handshake_CustomIP_TCP(t *testing.T) {
	testClient_Handshake_CustomIP(t, "tcp")
}

func testClient_Handshake_CustomIP(t *testing.T, network string) {
	srv := diamtest.NewServerNetwork(network, mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	cli := &Client{
		RetransmitInterval: testutil.NetworkTimeout(network, 3*time.Second),
		Handler:            mustNewStateMachine(t, clientSettings2),
		SupportedVendorID: []*diam.AVP{
			diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, clientSettings.VendorID),
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
		AuthApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		},
		VendorSpecificApplicationID: []*diam.AVP{
			diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
				},
			}),
		},
	}
	c, err := cli.DialNetwork(network, srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestClient_Handshake_Notify(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		SupportedVendorID: []*diam.AVP{
			diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, clientSettings.VendorID),
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
		AuthApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
		},
		VendorSpecificApplicationID: []*diam.AVP{
			diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
				},
			}),
		},
	}
	handshakeOK := testHandshakeNotifications(cli.Handler)
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-handshakeOK:
	case <-time.After(time.Second):
		t.Fatal("Handshake timed out")
	}
}

func TestClient_Handshake_FailParseCEA(t *testing.T) {
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		a := m.Answer(diam.Success)
		// Missing Origin-Host and other mandatory AVPs.
		mustWriteSMClientMessage(t, a, c)
	})
	srv := diamtest.NewServer(mux, dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	_, err := cli.Dial(srv.Addr)
	if err != smparser.ErrMissingOriginHost {
		t.Fatal(err)
	}
}

func TestClient_Handshake_FailedResultCode(t *testing.T) {
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		cer := new(smparser.CER)
		if _, err := cer.Parse(m, smparser.ParseOptions{Role: smparser.Server}); err != nil {
			panic(err)
		}
		a := m.Answer(diam.NoCommonApplication)
		mustSMClientAVP(t, a, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
		mustSMClientAVP(t, a, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
		if cer.OriginStateID != nil {
			a.AddAVP(cer.OriginStateID)
		}
		a.AddAVP(cer.AcctApplicationID[0]) // The one we send below.
		mustWriteSMClientMessage(t, a, c)
	})
	srv := diamtest.NewServer(mux, dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	_, err := cli.Dial(srv.Addr)
	if err == nil {
		t.Fatal("Unexpected CER worked")
	}
	e, ok := err.(*smparser.ErrFailedResultCode)
	if !ok {
		t.Fatal(err)
	}
	if !strings.Contains(e.Error(), "failed Result-Code AVP") {
		t.Fatal(e.Error())
	}
}

func TestClient_Handshake_RetransmitTimeout(t *testing.T) {
	mux := diam.NewServeMux()
	var retransmits uint32
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		// Do nothing to force timeout.
		atomic.AddUint32(&retransmits, 1)
	})
	srv := diamtest.NewServer(mux, dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler:            mustNewStateMachine(t, clientSettings),
		MaxRetransmits:     3,
		RetransmitInterval: time.Millisecond,
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := cli.DialContext(ctx, "tcp", srv.Addr, nil)
	if err == nil {
		t.Fatal("Unexpected CER worked")
	}
	if err != ErrHandshakeTimeout {
		t.Fatal(err)
	}
	// Dial returns once its last retransmission interval ends, which can be
	// before the server has read and dispatched the final CER. Wait for the
	// server to count all of them, then make sure no further CER arrives.
	deadline := time.Now().Add(time.Second)
	for atomic.LoadUint32(&retransmits) < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadUint32(&retransmits); n != 4 {
		t.Fatalf("Unexpected # of retransmits. Want 4, have %d", n)
	}
}

func TestClient_Watchdog(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	resp := make(chan struct{}, 1)
	cli := &Client{
		EnableWatchdog:   true,
		WatchdogInterval: 100 * time.Millisecond,
		watchdogTiming:   &watchdogTiming{floor: time.Millisecond},
		Handler:          mustNewStateMachine(t, clientSettings),
		OnWatchdogEvent: func(event WatchdogEvent) {
			if event == WatchdogAnswerReceived {
				resp <- struct{}{}
			}
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The first DWR is due after 100ms; the wait only bounds a missing DWA,
	// so it leaves room for a loaded scheduler.
	select {
	case <-resp:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for DWA")
	}
}

func TestClient_WatchdogObserverSuccess(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()

	events := make(chan WatchdogEvent, 4)
	cli := &Client{
		EnableWatchdog:   true,
		WatchdogInterval: 20 * time.Millisecond,
		watchdogTiming:   &watchdogTiming{floor: time.Millisecond},
		Handler:          mustNewStateMachine(t, clientSettings),
		OnWatchdogEvent:  func(event WatchdogEvent) { events <- event },
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogAnswerReceived} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("watchdog event = %q, want %q", got, want)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for watchdog event %q", want)
		}
	}
}

func TestClient_WatchdogSlowObserverDoesNotTimeoutSuccessfulAnswer(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()

	answerStarted := make(chan struct{})
	releaseAnswer := make(chan struct{})
	answerFinished := make(chan struct{})
	timedOut := make(chan struct{}, 1)
	var startedOnce, finishedOnce sync.Once
	cli := &Client{
		EnableWatchdog:     true,
		WatchdogInterval:   250 * time.Millisecond,
		watchdogTiming:     &watchdogTiming{floor: time.Millisecond},
		RetransmitInterval: 500 * time.Millisecond,
		Handler:            mustNewStateMachine(t, clientSettings),
		OnWatchdogEvent: func(event WatchdogEvent) {
			if event == WatchdogTimedOut {
				timedOut <- struct{}{}
				return
			}
			if event != WatchdogAnswerReceived {
				return
			}
			startedOnce.Do(func() { close(answerStarted) })
			<-releaseAnswer
			finishedOnce.Do(func() { close(answerFinished) })
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseAnswer) }) }
	defer release()

	select {
	case <-answerStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for answer observer")
	}
	select {
	case <-mustConnAs[diam.CloseNotifier](t, c).CloseNotify():
		t.Fatal("watchdog closed a healthy connection while the answer observer was blocked")
	case <-timedOut:
		t.Fatal("watchdog timed out a healthy connection while the answer observer was blocked")
	case <-time.After(7 * cli.WatchdogInterval):
	}
	release()
	select {
	case <-answerFinished:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for answer observer to return")
	}
	select {
	case <-mustConnAs[diam.CloseNotifier](t, c).CloseNotify():
		t.Fatal("watchdog closed a healthy connection after the answer observer returned")
	case <-timedOut:
		t.Fatal("watchdog timed out a healthy connection after the answer observer returned")
	case <-time.After(cli.WatchdogInterval):
	}
}

func TestClient_Watchdog_Timeout(t *testing.T) {
	sm := mustNewStateMachine(t, serverSettings)
	var once sync.Once
	sm.dwrHandler = handshakeOK(func(c diam.Conn, m *diam.Message) {
		once.Do(func() { mustWriteSMClientMessage(t, m.Answer(diam.UnableToComply), c) })
	})
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	events := make(chan WatchdogEvent, 2)
	cli := &Client{
		MaxRetransmits:     3,
		RetransmitInterval: 50 * time.Millisecond,
		EnableWatchdog:     true,
		WatchdogInterval:   50 * time.Millisecond,
		watchdogTiming:     &watchdogTiming{floor: time.Millisecond},
		Handler:            mustNewStateMachine(t, clientSettings),
		OnWatchdogEvent: func(event WatchdogEvent) {
			if event == WatchdogInvalidAnswer || event == WatchdogTimedOut {
				events <- event
			}
		},
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-mustConnAs[diam.CloseNotifier](t, c).CloseNotify():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for watchdog to disconnect client")
	}
	for _, want := range []WatchdogEvent{WatchdogInvalidAnswer, WatchdogTimedOut} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("watchdog event = %q, want %q", got, want)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for watchdog event %q", want)
		}
	}
}

// Type matching interface: net.Addr
type testLocalAddr struct {
	value string
}

func (a testLocalAddr) Network() string { return "tcp" }
func (a testLocalAddr) String() string  { return a.value }

// Type matching interface: diam.Conn
type testLocalAddrDiamConn struct {
	closed    atomic.Bool
	localAddr net.Addr
}

func (d *testLocalAddrDiamConn) Write(b []byte) (int, error)                    { return 0, nil }
func (d *testLocalAddrDiamConn) WriteStream(b []byte, stream uint) (int, error) { return 0, nil }
func (d *testLocalAddrDiamConn) Close()                                         { d.closed.Store(true) }
func (d *testLocalAddrDiamConn) Closed() bool                                   { return d.closed.Load() }
func (d *testLocalAddrDiamConn) LocalAddr() net.Addr                            { return d.localAddr }
func (d *testLocalAddrDiamConn) RemoteAddr() net.Addr                           { return nil }
func (d *testLocalAddrDiamConn) TLS() *tls.ConnectionState                      { return nil }
func (d *testLocalAddrDiamConn) Dictionary() *dict.Parser                       { return nil }
func (d *testLocalAddrDiamConn) Context() context.Context                       { return context.Background() }
func (d *testLocalAddrDiamConn) SetContext(c context.Context)                   {}
func (d *testLocalAddrDiamConn) Connection() net.Conn                           { return nil }

func newTestLocalAddrDiamConn(localAddrValue string) diam.Conn {
	return &testLocalAddrDiamConn{
		localAddr: &testLocalAddr{
			value: localAddrValue,
		},
	}
}

func requireLocalAddress(t *testing.T, got datatype.Address, want netip.Addr) {
	t.Helper()
	family := datatype.AddressFamilyIPv6
	if want.Is4() {
		family = datatype.AddressFamilyIPv4
	}
	expected := datatype.Address{Family: family, Value: want.AsSlice()}
	if got.Family != expected.Family || !bytes.Equal(got.Value, expected.Value) {
		t.Fatalf("address = {family: %d, value: %x}, want {family: %d, value: %x}",
			got.Family, got.Value, expected.Family, expected.Value)
	}
}

func TestClient_Conn_LocalAddresses_Loopback(t *testing.T) {
	c := newTestLocalAddrDiamConn("127.0.0.1:3868")

	addrList, err := getLocalAddresses(c)
	if err != nil {
		t.Fatalf("Failed to parse local addresses: %v", err)
	}
	if len(addrList) != 1 {
		t.Fatal("The only available loopback address was skipped")
	}
	requireLocalAddress(t, addrList[0], netip.MustParseAddr("127.0.0.1"))
}

func TestClient_Conn_LocalAddresses_Complex(t *testing.T) {
	c := newTestLocalAddrDiamConn("127.0.0.1/[::1%lo]/10.0.0.3/[fe80::78ef:0efb:a57b:15b9%eth0]:3868")

	addrList, err := getLocalAddresses(c)
	if err != nil {
		t.Fatalf("Failed to parse local addresses: %v", err)
	}
	if len(addrList) != 2 {
		t.Fatal("Failed to parse valid IP address or failed to skip loopback")
	}

	requireLocalAddress(t, addrList[0], netip.MustParseAddr("10.0.0.3"))
	requireLocalAddress(t, addrList[1], netip.MustParseAddr("fe80::78ef:efb:a57b:15b9"))
}

func TestClient_Conn_LocalAddresses_IPv6(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr net.Addr
	}{
		{"tcp", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3868}},
		{"string fallback", testLocalAddr{value: "[2001:db8::1]:3868"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getLocalAddresses(&testLocalAddrDiamConn{localAddr: tc.addr})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("addresses = %v, want 2001:db8::1", got)
			}
			requireLocalAddress(t, got[0], netip.MustParseAddr("2001:db8::1"))
		})
	}
}

func TestClient_Conn_LocalAddresses_SCTPMultihomed(t *testing.T) {
	addr := &sctp.Addr{IPs: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("2001:db8::1"),
	}, Port: 3868}
	got, err := getLocalAddresses(&testLocalAddrDiamConn{localAddr: addr})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("multihomed addresses = %v", got)
	}
	requireLocalAddress(t, got[0], netip.MustParseAddr("10.0.0.3"))
	requireLocalAddress(t, got[1], netip.MustParseAddr("2001:db8::1"))
	addr.IPs = []netip.Addr{netip.MustParseAddr("::1")}
	got, err = getLocalAddresses(&testLocalAddrDiamConn{localAddr: addr})
	if err != nil || len(got) != 1 {
		t.Fatalf("loopback-only addresses = %v, %v", got, err)
	}
	requireLocalAddress(t, got[0], netip.MustParseAddr("::1"))
}

func TestClientCustomLocalAddrRequiresIPLiteral(t *testing.T) {
	for _, tc := range []struct{ local, wantErr string }{
		{"diameter.example.net:3868", "failed to parse local IP"},
		{"", "empty local address"},
		{"192.0.2.1", "missing local address port"},
	} {
		t.Run(tc.local, func(t *testing.T) {
			cli := &Client{Handler: mustNewStateMachine(t, clientSettings)}
			conn := newTestLocalAddrDiamConn(tc.local)
			got, err := cli.handshake(conn, newWatchdogActivity())
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("handshake = (%v, %v), want %q", got, err, tc.wantErr)
			}
		})
	}
}

func TestClient_InbandSecurityID_Default(t *testing.T) {
	// RFC 6733 §6.10: the default zero value is omitted from CER.
	received := make(chan bool, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		a, err := m.FindAVP(avp.InbandSecurityID, 0)
		received <- err == nil && a != nil
		// Send a valid CEA back.
		cea := m.Answer(diam.Success)
		mustSMClientAVP(t, cea, avp.OriginHost, avp.Mbit, 0, serverSettings.OriginHost)
		mustSMClientAVP(t, cea, avp.OriginRealm, avp.Mbit, 0, serverSettings.OriginRealm)
		mustSMClientAVP(t, cea, avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1")))
		mustSMClientAVP(t, cea, avp.VendorID, avp.Mbit, 0, serverSettings.VendorID)
		mustSMClientAVP(t, cea, avp.ProductName, 0, 0, serverSettings.ProductName)
		mustSMClientAVP(t, cea, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))
		mustWriteSMClientMessage(t, cea, c)
	})
	srv := diamtest.NewServer(mux, dict.Default)
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
	}
	c, err := cli.Dial(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if <-received {
		t.Fatal("default CER includes Inband-Security-Id")
	}
}

func TestClient_InbandSecurityID_TLS(t *testing.T) {
	// Verify that setting InbandSecurityID=1 sends that value in CER.
	received := make(chan uint32, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
		a, err := m.FindAVP(avp.InbandSecurityID, 0)
		if err != nil {
			t.Fatal(err)
		}
		if a != nil {
			received <- uint32(a.Data.(datatype.Unsigned32))
		}
		cea := m.Answer(diam.Success)
		mustSMClientAVP(t, cea, avp.OriginHost, avp.Mbit, 0, serverSettings.OriginHost)
		mustSMClientAVP(t, cea, avp.OriginRealm, avp.Mbit, 0, serverSettings.OriginRealm)
		mustSMClientAVP(t, cea, avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1")))
		mustSMClientAVP(t, cea, avp.VendorID, avp.Mbit, 0, serverSettings.VendorID)
		mustSMClientAVP(t, cea, avp.ProductName, 0, 0, serverSettings.ProductName)
		mustSMClientAVP(t, cea, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))
		mustWriteSMClientMessage(t, cea, c)
	})
	srv := diamtest.NewUnstartedServer(mux, dict.Default)
	srv.StartTLS()
	defer srv.Close()
	cli := &Client{
		Handler: mustNewStateMachine(t, clientSettings),
		AcctApplicationID: []*diam.AVP{
			diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3)),
		},
		InbandSecurityID: 1,
		TLSConfig:        &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test server certificate
	}
	c, err := cli.DialTLS(srv.Addr, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-received; got != 1 {
		t.Fatalf("Expected Inband-Security-Id=1, got %d", got)
	}
}

func (d *testLocalAddrDiamConn) Logger() *slog.Logger { return slog.Default() }
