package sm

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §§8.3.1, 8.4.1, 8.5.1, 9.7.1: independent minimal requests.
func baseSessionRequest(code uint32) *diam.Message {
	m := diam.NewMessage(code, diam.RequestFlag|diam.ProxiableFlag, 0, 0x12345678, 0x87654321, dict.Default)
	m.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("original-session")))
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("client.example")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if code == diam.Accounting {
		m.AddAVP(diam.NewAVP(avp.AccountingRecordType, avp.Mbit, 0, datatype.Enumerated(1)))
		m.AddAVP(diam.NewAVP(avp.AccountingRecordNumber, avp.Mbit, 0, datatype.Unsigned32(17)))
	} else {
		m.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0)))
		if code != diam.SessionTermination {
			m.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("server.example")))
		}
		if code == diam.ReAuth {
			m.AddAVP(diam.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Enumerated(0)))
		}
		if code == diam.SessionTermination {
			m.AddAVP(diam.NewAVP(avp.TerminationCause, avp.Mbit, 0, datatype.Enumerated(1)))
		}
	}
	return m
}

// RFC 6733 §§3.2, 6.2, 7.1.5, 7.2; Verified Erratum 4808.
// Exercise real validation dispatch and the shared error-answer builder on TCP.
func TestBaseSessionErrorsTCP(t *testing.T) {
	for _, command := range []struct{ code, app uint32 }{{diam.ReAuth, 0}, {diam.SessionTermination, 0}, {diam.AbortSession, 0}, {diam.Accounting, 0}, {diam.Accounting, 3}} {
		code := command.code
		for _, kind := range []string{"duplicate", "displaced", "missing", "missing-nested", "protocol-missing"} {
			t.Run(fmt.Sprintf("%d/%d/%s", command.app, code, kind), func(t *testing.T) {
				settings := testMessageErrorSettings()
				settings.ValidateRequests = true
				handler := mustNewStateMachine(t, settings)
				server := diamtest.NewServer(handler, dict.Default)
				defer server.Close()
				conn := dialHandshakeUnknownTest(t, server.Addr)
				defer func() { _ = conn.Close() }()
				request := baseSessionRequest(code)
				request.Header.ApplicationID = command.app
				if err := request.ValidateOutgoing(); err != nil {
					t.Fatalf("valid request: %v", err)
				}
				expected := uint32(diam.MissingAVP)
				flags := uint8(diam.ProxiableFlag)
				var evidence *diam.AVP
				switch kind {
				case "duplicate":
					evidence = diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("first-excess"))
					request.AddAVP(evidence)
					request.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("later-excess")))
					expected = diam.AVPOccursTooManyTimes
				case "displaced":
					request.AVP[0], request.AVP[1] = request.AVP[1], request.AVP[0]
					expected = diam.AVPNotAllowed
				case "missing", "missing-nested":
					original := request.AVP[0]
					request.AVP = request.AVP[1:]
					if kind == "missing-nested" {
						request.AddAVP(diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
							diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")),
							diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("state")), original,
						}}))
					}
				case "protocol-missing":
					request.AVP = request.AVP[1:]
					request.Header.CommandFlags |= diam.ErrorFlag
					expected = diam.InvalidHDRBits
					flags |= diam.ErrorFlag
				}
				if _, err := request.WriteTo(conn); err != nil {
					t.Fatal(err)
				}
				if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				answer, err := diam.ReadMessage(conn, dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if !testResultCode(answer, expected) || answer.Header.CommandFlags != flags {
					t.Fatalf("answer: %v", answer)
				}
				if answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
					t.Fatal("correlation IDs changed")
				}
				if err := answer.Validate(); err != nil {
					t.Fatalf("answer validation: %v", err)
				}
				var session *diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.SessionID && a.VendorID == 0 {
						session = a
						break
					}
				}
				if kind == "missing" || kind == "missing-nested" || kind == "protocol-missing" {
					if session != nil {
						t.Fatalf("invented Session-Id: %v", session)
					}
				} else if session == nil || session.Data != datatype.UTF8String("original-session") || answer.AVP[0] != session {
					t.Fatalf("session not copied to prefix: %v", session)
				}
				if kind == "protocol-missing" {
					return
				}
				var failed []*diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.FailedAVP && a.VendorID == 0 {
						failed = append(failed, a)
					}
				}
				if len(failed) != 1 {
					t.Fatalf("Failed-AVP count %d", len(failed))
				}
				group, ok := failed[0].Data.(*diam.GroupedAVP)
				if !ok || len(group.AVP) != 1 {
					t.Fatalf("evidence: %v", failed[0])
				}
				if kind == "missing" || kind == "missing-nested" {
					v := group.AVP[0]
					if v.Code != avp.SessionID || v.VendorID != 0 || v.Data.Len() != 0 {
						t.Fatalf("missing example: %v", v)
					}
				}
				if evidence != nil {
					want, err := evidence.Serialize()
					if err != nil {
						t.Fatal(err)
					}
					got, err := group.AVP[0].Serialize()
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("first excess not retained: %x versus %x (%v)", got, want, err)
					}
				}
			})
		}
	}
}
