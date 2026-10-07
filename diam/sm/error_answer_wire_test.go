package sm

import (
	"bytes"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §§6.2, 7.1.5, 7.5: errors still receive an answer when
// Session-Id cannot be decoded. Proxy-Info survives all answer classes.
func TestStateMachineErrorAnswersOnWire(t *testing.T) {
	for _, kind := range []string{"length7", "unknown-no-session", "proxy-2001", "proxy-3001", "proxy-5001"} {
		t.Run(kind, func(t *testing.T) {
			settings := testMessageErrorSettings()
			settings.RejectUnknownMandatoryAVPs = true
			settings.ValidateRequests = true
			h := mustNewStateMachine(t, settings)
			h.HandleFunc("STR", func(c diam.Conn, r *diam.Message) {
				a := r.Answer(diam.Success)
				a.InsertAVP(r.AVP[0])
				a.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, settings.OriginHost))
				a.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm))
				if _, err := a.WriteTo(c); err != nil {
					t.Error(err)
				}
			})
			srv := diamtest.NewServer(h, dict.Default)
			defer srv.Close()
			conn := dialHandshakeUnknownTest(t, srv.Addr)
			defer func() { _ = conn.Close() }()
			r := baseSessionRequest(diam.SessionTermination)
			result := uint32(diam.Success)
			var proxies []*diam.AVP
			if kind == "unknown-no-session" {
				r.AVP = r.AVP[1:]
			}
			if kind == "unknown-no-session" || kind == "proxy-5001" {
				r.AddAVP(diam.NewAVP(999999, avp.Mbit, 0, datatype.Unknown{1}))
				result = diam.AVPUnsupported
			}
			if kind == "proxy-3001" {
				r.Header.CommandCode = 0xfffffe
				result = diam.CommandUnsupported
			}
			if kind == "length7" {
				result = diam.InvalidAVPLength
			} else if kind != "unknown-no-session" {
				for _, state := range []string{"first", "second"} {
					p := diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")), diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString(state))}})
					proxies = append(proxies, p)
					r.AddAVP(p)
				}
			}
			wire, err := r.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "length7" {
				wire[25], wire[26], wire[27] = 0, 0, 7
			}
			if _, err := conn.Write(wire); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			a, err := diam.ReadMessage(conn, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if !testResultCode(a, result) || a.Header.HopByHopID != r.Header.HopByHopID || a.Header.EndToEndID != r.Header.EndToEndID {
				t.Fatalf("answer: %v", a)
			}
			if err := a.Validate(); err != nil {
				t.Fatal(err)
			}
			if kind == "length7" || kind == "unknown-no-session" {
				if len(a.FindAVPsWithPath(diam.AVPRef{Code: avp.SessionID})) != 0 {
					t.Fatal("invented Session-Id")
				}
				failed := a.FindAVPsWithPath(diam.AVPRef{Code: avp.FailedAVP})
				if len(failed) != 1 {
					t.Fatalf("Failed-AVP count %d", len(failed))
				}
				evidence := failed[0].Data.(*diam.GroupedAVP).AVP
				if len(evidence) != 1 {
					t.Fatal("wrong evidence count")
				}
				want := uint32(avp.SessionID)
				if kind == "unknown-no-session" {
					want = 999999
				}
				if evidence[0].Code != want {
					t.Fatal("wrong evidence")
				}
			}
			got := a.FindAVPsWithPath(diam.AVPRef{Code: avp.ProxyInfo})
			if len(got) != len(proxies) {
				t.Fatalf("Proxy-Info count %d, want %d", len(got), len(proxies))
			}
			for i, p := range got {
				if !bytes.Equal(p.Data.Serialize(), proxies[i].Data.Serialize()) {
					t.Fatal("proxy order or contents changed")
				}
			}
			t.Logf("result=%d proxies=%d", result, len(got))
		})
	}
}
