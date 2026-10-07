package base_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 6733 §6.2 applies to every answer, including all error classes.
// Iterate every effective command, including inherited common commands.
func TestFixErrorAnswerEveryCommand(t *testing.T) {
	codes := map[uint32]bool{}
	apps := map[uint32]bool{}
	for _, a := range dict.Default.Apps() {
		apps[a.ID] = true
		for _, c := range a.Command {
			codes[c.Code] = true
		}
	}
	seen := 0
	for app := range apps {
		for code := range codes {
			c, err := dict.Default.FindCommand(app, code)
			if err != nil || len(c.Answer.Rule) == 0 {
				continue
			}
			seen++
			for _, result := range []uint32{diam.UnableToDeliver, diam.AuthenticationRejected, diam.AVPUnsupported, diam.MissingAVP, diam.InvalidAVPLength} {
				for _, kind := range []string{"absent", "undecodable", "present"} {
					t.Run(fmt.Sprintf("%d/%d/%d/%s", app, code, result, kind), func(t *testing.T) {
						flags := uint8(diam.RequestFlag)
						if c.Request.Proxiable != nil && *c.Request.Proxiable {
							flags |= diam.ProxiableFlag
						}
						r := diam.NewMessage(code, flags, app, 0x12345678, 0x87654321, dict.Default)
						if kind == "present" {
							r.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("original")))
						}
						if kind == "undecodable" {
							r.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.Unknown{}))
						}
						a, err := base.BuildErrorAnswer(r, fixtureSettings(), result, nil, result >= 3000 && result < 4000)
						if err != nil {
							t.Fatal(err)
						}
						sid := a.FindAVPsWithPath(diam.AVPRef{Code: avp.SessionID})
						if kind == "present" {
							if len(sid) != 1 || sid[0].Data != datatype.UTF8String("original") {
								t.Fatalf("lost session: %v", sid)
							}
						} else if len(sid) != 0 {
							t.Fatalf("invented Session-Id: %v", sid)
						}
						if len(a.FindAVPsWithPath(diam.AVPRef{Code: avp.FailedAVP})) != 0 {
							t.Fatal("invented Failed-AVP")
						}
						requiresSession := false
						for _, rule := range c.Answer.Rule {
							if rule.AVP == "Session-Id" && (rule.Required || rule.Min > 0) {
								requiresSession = true
							}
						}
						strictErr := a.ValidateOutgoing()
						if kind != "present" && result >= 4000 && requiresSession {
							if strictErr == nil || strictErr.ResultCode != diam.MissingAVP || strictErr.FailedAVP == nil || strictErr.FailedAVP.Code != avp.SessionID {
								t.Fatalf("public outgoing check relaxed: %v", strictErr)
							}
						} else if strictErr != nil {
							t.Fatal(strictErr)
						}
						wire, err := a.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						got, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
						if err != nil {
							t.Fatal(err)
						}
						if err := got.Validate(); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
	t.Logf("%d effective commands across %d applications", seen, len(apps))
}

// RFC 6733 §6.2 requires the proxy chain in both protocol and application errors.
func TestFixErrorAnswerProxyInfo(t *testing.T) {
	r := diam.NewRequest(diam.SessionTermination, 0, dict.Default)
	for _, state := range []string{"first", "second"} {
		r.AddAVP(diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")), diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString(state))}}))
	}
	for _, result := range []uint32{diam.UnableToDeliver, diam.AVPUnsupported} {
		t.Run(fmt.Sprint(result), func(t *testing.T) {
			a, err := base.BuildErrorAnswer(r, fixtureSettings(), result, nil, result == diam.UnableToDeliver)
			if err != nil {
				t.Fatal(err)
			}
			proxies := a.FindAVPsWithPath(diam.AVPRef{Code: avp.ProxyInfo})
			if len(proxies) != 2 {
				t.Fatalf("Proxy-Info count=%d", len(proxies))
			}
			for i, p := range proxies {
				if !bytes.Equal(p.Data.Serialize(), r.AVP[i].Data.Serialize()) {
					t.Fatal("proxy order or contents changed")
				}
			}
		})
	}
}
