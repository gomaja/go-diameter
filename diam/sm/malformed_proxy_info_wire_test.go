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

// RFC 6733 §§4.1, 6.2: echoed peer data retains everything except reserved flag bits.
func TestMalformedProxyInfoAnsweredOnTCP(t *testing.T) {
	for _, kind := range []string{"m-clear", "reserved", "host-m-clear", "extension-reserved", "state-missing", "host-duplicate", "empty"} {
		for _, result := range []uint32{3001, 5014, 5001, 5005} {
			t.Run(fmt.Sprintf("%s/%d", kind, result), func(t *testing.T) {
				settings := testMessageErrorSettings()
				settings.RejectUnknownMandatoryAVPs = true
				settings.ValidateRequests = true
				h := mustNewStateMachine(t, settings)
				srv := diamtest.NewServer(h, dict.Default)
				defer srv.Close()
				conn := dialHandshakeUnknownTest(t, srv.Addr)
				defer func() { _ = conn.Close() }()
				r := baseSessionRequest(diam.SessionTermination)
				host := diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example"))
				g := &diam.GroupedAVP{AVP: []*diam.AVP{host, diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("echo-state"))}}
				p := diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, g)
				switch kind {
				case "m-clear":
					p.Flags = 0
				case "reserved":
					p.Flags |= 1
				case "host-m-clear":
					host.Flags = 0
				case "extension-reserved":
					g.AVP = append(g.AVP, diam.NewAVP(999998, 1, 0, datatype.Unknown{1, 2, 3}))
				case "state-missing":
					g.AVP = g.AVP[:1]
				case "host-duplicate":
					g.AVP = append(g.AVP, host)
				case "empty":
					g.AVP = nil
				}
				r.AddAVP(p)
				switch result {
				case 3001:
					r.Header.CommandCode = 0xfffffe
				case 5014:
					r.AddAVP(diam.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unknown{1}))
				case 5001:
					r.AddAVP(diam.NewAVP(999999, avp.Mbit, 0, datatype.Unknown{1}))
				case 5005:
					r.AVP = r.AVP[1:]
				}
				raw, err := r.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = conn.Write(raw); err != nil {
					t.Fatal(err)
				}
				if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				a, err := diam.ReadMessage(conn, dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if !testResultCode(a, result) || a.Header.HopByHopID != r.Header.HopByHopID || a.Header.EndToEndID != r.Header.EndToEndID {
					t.Fatalf("wrong answer: %v", a)
				}
				echoes := a.FindAVPsWithPath(diam.AVPRef{Code: avp.ProxyInfo})
				if len(echoes) != 1 {
					t.Fatalf("echo count %d", len(echoes))
				}
				for _, member := range g.AVP {
					member.Flags &^= 0x1f
				}
				if echoes[0].Flags != p.Flags&^0x1f || !bytes.Equal(echoes[0].Data.Serialize(), p.Data.Serialize()) {
					t.Fatal("echo bytes changed")
				}
			})
		}
	}
}
