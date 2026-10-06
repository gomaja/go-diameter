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

func TestDictionaryValidationTCP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		change  func(*diam.Message)
		code    uint32
		flags   uint8
		failed  uint32
	}{
		{"off", false, func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("duplicate")))
		}, 0, 0, 0},
		{"excess", true, func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("duplicate")))
		}, diam.AVPOccursTooManyTimes, diam.ProxiableFlag, avp.SessionID},
		{"invalid-header", true, func(m *diam.Message) { m.Header.CommandFlags |= diam.ErrorFlag }, diam.InvalidHDRBits, diam.ProxiableFlag | diam.ErrorFlag, 0},
		{"invalid-avp-bits", true, func(m *diam.Message) { m.AVP[0].Flags |= avp.Vbit }, diam.InvalidAVPBits, diam.ProxiableFlag | diam.ErrorFlag, avp.SessionID},
		{"missing", true, func(m *diam.Message) { m.AVP = m.AVP[:len(m.AVP)-1] }, diam.MissingAVP, diam.ProxiableFlag, avp.ReAuthRequestType},
		{"missing-session", true, func(m *diam.Message) { m.AVP = m.AVP[1:] }, diam.MissingAVP, diam.ProxiableFlag, avp.SessionID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.ValidateRequests = tc.enabled
			sm := mustNewStateMachine(t, settings)
			seen := make(chan struct{}, 1)
			sm.HandleFunc("RAR", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			conn := dialHandshakeUnknownTest(t, srv.Addr)
			defer func() { _ = conn.Close() }()
			request := unknownRequest(false, 0)
			request.AVP = request.AVP[:len(request.AVP)-1]
			tc.change(request)
			request.Header.MessageLength = uint32(request.Len())
			if _, err := request.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			if tc.code == 0 {
				select {
				case <-seen:
				case <-time.After(time.Second):
					t.Fatal("permissive handler not called")
				}
				return
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			answer, err := diam.ReadMessage(conn, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if !testResultCode(answer, tc.code) || answer.Header.CommandFlags != tc.flags {
				t.Fatalf("answer = %v, flags %#x", answer, answer.Header.CommandFlags)
			}
			if validationErr := answer.Validate(); validationErr != nil {
				t.Fatalf("error answer violates dictionary: %v", validationErr)
			}
			if answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
				t.Fatal("answer IDs changed")
			}
			if tc.failed != 0 {
				failed, err := answer.FindAVP(avp.FailedAVP, 0)
				if err != nil {
					t.Fatal(err)
				}
				children := failed.Data.(*diam.GroupedAVP).AVP
				if len(children) != 1 || children[0].Code != tc.failed {
					t.Fatalf("Failed-AVP = %v", children)
				}
			}
			select {
			case <-seen:
				t.Fatal("invalid request dispatched")
			default:
			}
		})
	}
}

func TestDictionaryValidationNeverAnswersAnswer(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.ValidateRequests = true
	sm := mustNewStateMachine(t, settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn := dialHandshakeUnknownTest(t, srv.Addr)
	defer func() { _ = conn.Close() }()
	answer := diam.NewMessage(diam.ReAuth, diam.ProxiableFlag, 0, 1, 2, dict.Default)
	if _, err := answer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("unexpected answer to answer: %v", err)
	}
}

func TestDictionaryValidationKeepsUnknownMandatoryResult(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.ValidateRequests = true
	settings.RejectUnknownMandatoryAVPs = true
	sm := mustNewStateMachine(t, settings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn := dialHandshakeUnknownTest(t, srv.Addr)
	defer func() { _ = conn.Close() }()
	request := unknownRequest(false, avp.Mbit)
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
	if !testResultCode(answer, diam.AVPUnsupported) || answer.Header.CommandFlags != diam.ProxiableFlag {
		t.Fatalf("combined option answer: %v", answer)
	}
	if validationErr := answer.Validate(); validationErr != nil {
		t.Fatalf("5001 answer: %v", validationErr)
	}
}

func TestDictionaryValidationUnderstoodFlagsTCP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*diam.Message)
		code   uint32
	}{
		{"must-not M set", func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(avp.FirmwareRevision, avp.Mbit, 0, datatype.Unsigned32(1)))
		}, diam.Success},
		{"must M clear", func(m *diam.Message) { m.AVP[0].Flags = 0 }, diam.Success},
		{"reserved P set", func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(avp.FirmwareRevision, avp.Pbit, 0, datatype.Unsigned32(1)))
		}, diam.Success},
		{"reserved R set", func(m *diam.Message) { m.AVP[0].Flags |= 0x1f }, diam.Success},
		{"reserved command bits", func(m *diam.Message) { m.Header.CommandFlags |= 0x0f }, diam.Success},
		{"V mismatch", func(m *diam.Message) { m.AVP[0].Flags |= avp.Vbit }, diam.InvalidAVPBits},
		{"unknown mandatory", func(m *diam.Message) {
			m.AddAVP(diam.NewAVP(0xfedc, avp.Mbit, 0, datatype.OctetString("unknown")))
		}, diam.AVPUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.ValidateRequests = true
			settings.RejectUnknownMandatoryAVPs = true
			sm := mustNewStateMachine(t, settings)
			sm.HandleFunc("RAR", func(c diam.Conn, m *diam.Message) {
				answer := m.Answer(0)
				answer.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, m.AVP[0].Data))
				answer.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
				answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, settings.OriginHost))
				answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm))
				if _, err := answer.WriteTo(c); err != nil {
					t.Error(err)
				}
			})
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			conn := dialHandshakeUnknownTest(t, srv.Addr)
			defer func() { _ = conn.Close() }()
			request := unknownRequest(false, 0)
			request.AVP = request.AVP[:len(request.AVP)-1]
			tc.change(request)
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
			if !testResultCode(answer, tc.code) {
				t.Fatalf("want result %d, got %v", tc.code, answer)
			}
			if err := answer.ValidateOutgoing(); err != nil {
				t.Fatalf("outgoing answer: %v", err)
			}
		})
	}
}

func TestDictionaryValidationCreditControlAnswerTCP(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.ValidateRequests = true
	sm := mustNewStateMachine(t, settings)
	seen := make(chan struct{}, 1)
	sm.HandleFunc("CCR", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn := dialHandshakeUnknownTest(t, srv.Addr)
	defer func() { _ = conn.Close() }()
	request := diam.NewMessage(diam.CreditControl, diam.RequestFlag|diam.ProxiableFlag, 4, 0x11223344, 0x55667788, dict.Default)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.SessionID, datatype.UTF8String("session")},
		{avp.OriginHost, datatype.DiameterIdentity("peer.example")},
		{avp.OriginRealm, datatype.DiameterIdentity("example")},
		{avp.DestinationRealm, datatype.DiameterIdentity("example")},
		{avp.AuthApplicationID, datatype.Unsigned32(4)},
		{avp.ServiceContextID, datatype.UTF8String("service")},
		{avp.CCRequestType, datatype.Enumerated(2)},
		{avp.CCRequestNumber, datatype.Unsigned32(7)},
		{avp.CCRequestNumber, datatype.Unsigned32(8)},
	} {
		request.AddAVP(diam.NewAVP(field.code, avp.Mbit, 0, field.value))
	}
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
	if !testResultCode(answer, diam.AVPOccursTooManyTimes) || answer.Header.CommandFlags != diam.ProxiableFlag {
		t.Fatalf("CCA result/flags: %v", answer)
	}
	if validationErr := answer.Validate(); validationErr != nil {
		t.Fatalf("CCA grammar: %v", validationErr)
	}
	for _, field := range []struct {
		code uint32
		want uint32
	}{
		{avp.AuthApplicationID, 4}, {avp.CCRequestType, 2}, {avp.CCRequestNumber, 7},
	} {
		var a *diam.AVP
		for _, candidate := range answer.AVP {
			if candidate.Code == field.code && candidate.VendorID == 0 {
				a = candidate
				break
			}
		}
		if a == nil {
			t.Fatalf("answer missing AVP %d", field.code)
		}
		var got uint32
		switch v := a.Data.(type) {
		case datatype.Unsigned32:
			got = uint32(v)
		case datatype.Enumerated:
			got = uint32(v)
		default:
			t.Fatalf("answer AVP %d type %T", field.code, a.Data)
		}
		if got != field.want {
			t.Fatalf("answer AVP %d = %d, want %d", field.code, got, field.want)
		}
	}
	select {
	case <-seen:
		t.Fatal("invalid CCR dispatched")
	default:
	}
}
