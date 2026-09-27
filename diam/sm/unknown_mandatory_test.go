package sm

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestUnknownMandatoryAVPAnswerTCP(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "top", true: "nested"}[nested], func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.RejectUnknownMandatoryAVPs = true
			sm := New(settings)
			seen := make(chan struct{}, 1)
			sm.HandleFunc("RAR", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			conn := dialHandshakeUnknownTest(t, srv.Addr)
			defer func() { _ = conn.Close() }()
			request := unknownRequest(nested, avp.Mbit)
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
			if !testResultCode(answer, diam.AVPUnsupported) {
				t.Fatalf("result code: %v", answer)
			}
			if validationErr := answer.Validate(); validationErr != nil {
				t.Fatalf("5001 answer violates dictionary: %v", validationErr)
			}
			if answer.Header.CommandFlags != diam.ProxiableFlag {
				t.Fatalf("5001 answer flags = %#x, want P without E", answer.Header.CommandFlags)
			}
			if answer.AVP[0].Code != avp.SessionID || answer.AVP[1].Code != avp.ResultCode {
				t.Fatalf("RAA AVP order starts %d,%d, want Session-Id,Result-Code", answer.AVP[0].Code, answer.AVP[1].Code)
			}
			if answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
				t.Fatalf("answer identifiers = %+v", answer.Header)
			}
			if _, err := answer.FindAVP(avp.OriginHost, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := answer.FindAVP(avp.OriginRealm, 0); err != nil {
				t.Fatal(err)
			}
			failed, err := answer.FindAVP(avp.FailedAVP, 0)
			if err != nil {
				t.Fatal(err)
			}
			roots := failed.Data.(*diam.GroupedAVP).AVP
			if len(roots) != 1 {
				t.Fatalf("Failed-AVP roots = %d", len(roots))
			}
			if nested {
				if roots[0].Code != avp.VendorSpecificApplicationID {
					t.Fatalf("Failed-AVP parent = %d", roots[0].Code)
				}
				roots = roots[0].Data.(*diam.GroupedAVP).AVP
			}
			if len(roots) != 1 || roots[0].Code != 0xfedc || roots[0].VendorID != 10415 || roots[0].Flags&avp.Mbit == 0 || string(roots[0].Data.(datatype.Unknown)) != "bad" {
				t.Fatalf("failed unknown = %+v", roots)
			}
			select {
			case <-seen:
				t.Fatal("application handler received rejected request")
			default:
			}
		})
	}
}

func TestUnknownAVPToleranceTCP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		flag    uint8
	}{
		{"default-off-mandatory", false, avp.Mbit},
		{"enabled-optional", true, 0},
		{"default-off-optional", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.RejectUnknownMandatoryAVPs = tc.enabled
			sm := New(settings)
			seen := make(chan struct{}, 1)
			sm.HandleFunc("RAR", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			conn := dialHandshakeUnknownTest(t, srv.Addr)
			defer func() { _ = conn.Close() }()
			if _, err := unknownRequest(false, tc.flag).WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			select {
			case <-seen:
			case <-time.After(time.Second):
				t.Fatal("handler did not receive tolerated request")
			}
			if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			_, err := diam.ReadMessage(conn, dict.Default)
			var nerr net.Error
			if !errors.As(err, &nerr) || !nerr.Timeout() {
				t.Fatalf("unexpected response: %v", err)
			}
		})
	}
}

func TestUnknownMandatoryAnswerIsNotAnswered(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.RejectUnknownMandatoryAVPs = true
	sm := New(settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn := dialHandshakeUnknownTest(t, srv.Addr)
	defer func() { _ = conn.Close() }()
	m := unknownRequest(false, avp.Mbit)
	m.Header.CommandFlags &^= diam.RequestFlag
	if _, err := m.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("unexpected response: %v", err)
	}
}

func TestUnknownMandatoryMultipleFailuresOneContainer(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.RejectUnknownMandatoryAVPs = true
	sm := New(settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn := dialHandshakeUnknownTest(t, srv.Addr)
	defer func() { _ = conn.Close() }()
	m := unknownRequest(false, avp.Mbit)
	m.AddAVP(diam.NewAVP(0xfedd, avp.Mbit|avp.Vbit, 10415, datatype.OctetString("second")))
	if _, err := m.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if !testResultCode(answer, diam.AVPUnsupported) {
		t.Fatalf("result code: %v", answer)
	}
	var failed []*diam.AVP
	for _, a := range answer.AVP {
		if a.Code == avp.FailedAVP {
			failed = append(failed, a)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("Failed-AVP count = %d, want 1", len(failed))
	}
	children := failed[0].Data.(*diam.GroupedAVP).AVP
	if len(children) != 2 || children[0].Code != 0xfedc || children[1].Code != 0xfedd {
		t.Fatalf("Failed-AVP children = %+v", children)
	}
}

func unknownRequest(nested bool, mandatory uint8) *diam.Message {
	m := diam.NewMessage(diam.ReAuth, diam.RequestFlag|diam.ProxiableFlag, 0, 0x11223344, 0x55667788, dict.Default)
	m.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("test-session")))
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("server.example")))
	m.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0)))
	m.AddAVP(diam.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Enumerated(0)))
	bad := diam.NewAVP(0xfedc, mandatory|avp.Vbit, 10415, datatype.OctetString("bad"))
	if nested {
		m.AddAVP(diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{bad}}))
	} else {
		m.AddAVP(bad)
	}
	return m
}

func dialHandshakeUnknownTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	writeValidSMErrorCER(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := diam.ReadMessage(conn, dict.Default); err != nil {
		t.Fatal(err)
	}
	return conn
}
