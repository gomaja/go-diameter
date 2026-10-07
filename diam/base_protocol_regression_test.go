package diam

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §§6.2, 7.1 and 7.1.5: error answers may lack Session-Id;
// Failed-AVP is recommended, not a prerequisite for answering.
func TestReceivedErrorAnswers(t *testing.T) {
	for _, result := range []uint32{1001, 2001, 3001, 4001, 5001, 5005, 5014} {
		for _, evidence := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/evidence_%t", result, evidence), func(t *testing.T) {
				m := baseMissingAnswer()
				m.AVP[0].Data = datatype.Unsigned32(result)
				if !evidence {
					m.AVP = m.AVP[:3]
				}
				if result >= 3000 && result < 4000 {
					m.Header.CommandFlags |= ErrorFlag
				}
				for _, check := range []func() *ValidationError{m.Validate} {
					err := check()
					if (err == nil) != (result >= 3000) {
						t.Fatalf("result %d: %v", result, err)
					}
				}
				if result >= 3000 {
					m.AVP = append(m.AVP[:1], m.AVP[2:]...)
					if err := m.Validate(); err == nil || err.ResultCode != MissingAVP {
						t.Fatalf("Origin-Host omission accepted: %v", err)
					}
				}
			})
		}
	}
	t.Run("Experimental-Result singleton", func(t *testing.T) {
		m := baseMissingAnswer()
		m.Header.CommandFlags |= ErrorFlag
		m.AVP[0].Data = datatype.Unsigned32(UnableToDeliver)
		e := NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)), NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(5001))}})
		m.AddAVP(e)
		if err := m.ValidateOutgoing(); err != nil {
			t.Fatal(err)
		}
		m.AddAVP(e)
		if err := m.ValidateOutgoing(); err == nil || err.ResultCode != AVPOccursTooManyTimes || err.FailedAVP != e {
			t.Fatalf("duplicate Experimental-Result: %v", err)
		}
	})
}

// RFC 6733 §§3.2, 4.1, 7.1.5 and 8.8: ignore unknown optional AVPs
// for fixed placement, and identify the misplaced fixed AVP as evidence.
func TestFixedPositionEvidence(t *testing.T) {
	_, commands := baseWireSpec(t)
	for _, c := range commands {
		if !c.Request || !c.Rules[0].Fixed {
			continue
		}
		t.Run(c.Section, func(t *testing.T) {
			m := baseCommandMessage(t, 0, c)
			m.InsertAVP(NewAVP(999999, 0, 0, datatype.Unknown{1}))
			if err := m.Validate(); err != nil {
				t.Errorf("unknown optional prefix: %v", err)
			}
			m = baseCommandMessage(t, 0, c)
			sid := m.AVP[0]
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed || err.FailedAVP != sid {
				t.Fatalf("misplaced evidence: %v", err)
			}
		})
	}
}

// RFC 6733 §3.2: arbitrary AVPs satisfy minima; §4.1: unknown AVPs
// never cause a wildcard maximum rejection. Named members count in neither.
func TestWildcardUnknownMinimum(t *testing.T) {
	rules := []*dict.Rule{{AVP: "AVP", Min: 1, Max: 1, MaxSet: true}}
	unknown := NewAVP(999999, 0, 0, datatype.Unknown{1})
	known := NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("user"))
	for _, items := range [][]*AVP{{unknown}, {unknown, unknown}, {known, unknown}} {
		if err := validateAVPs(items, rules, 0, dict.Default.Snapshot()); err != nil {
			t.Errorf("unknown minimum: %v", err)
		}
	}
	if err := validateAVPs([]*AVP{known, known}, rules, 0, dict.Default.Snapshot()); err == nil || err.ResultCode != AVPOccursTooManyTimes {
		t.Fatalf("known maximum: %v", err)
	}
	if err := validateAVPs(nil, rules, 0, dict.Default.Snapshot()); err == nil || err.ResultCode != MissingAVP || err.FailedAVP != nil {
		t.Fatalf("top-level missing arbitrary AVP: %v", err)
	}
}

func fixProxy(state string) *AVP {
	return NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")), NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString(state))}})
}

// RFC 6733 §6.2: every request Proxy-Info is returned in original order.
func TestAnswerProxyInfo(t *testing.T) {
	r := NewRequest(SessionTermination, 0, dict.Default)
	r.AddAVP(fixProxy("first"))
	r.AddAVP(fixProxy("second"))
	r.AddAVP(NewAVP(avp.ProxyInfo, avp.Vbit, 777, &GroupedAVP{}))
	r.AddAVP(NewAVP(999998, 0, 0, &GroupedAVP{AVP: []*AVP{fixProxy("nested")}}))
	a := r.Answer(Success)
	wire, err := a.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AVP) != 3 {
		t.Fatalf("unexpected copied AVPs: %v", got.AVP)
	}
	proxies := got.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})
	if len(proxies) != 2 {
		t.Fatalf("Proxy-Info count=%d", len(proxies))
	}
	for i, p := range proxies {
		if !bytes.Equal(p.Data.Serialize(), r.AVP[i].Data.Serialize()) {
			t.Fatal("Proxy-Info order or bytes changed")
		}
	}
}

// RFC 7075 §§3.3–3.4: no AVP-specific M rule is prescribed; RFC 6733
// §4.1 clears V for this IETF AVP. Realm redirection uses protocol error 3011.
func TestRealmRedirect(t *testing.T) {
	if RealmRedirectIndication != 3011 {
		t.Fatal("RFC 7075 §3.4 result code")
	}
	for _, app := range []uint32{0, 3} {
		d, err := dict.Default.FindAVP(app, 620, 0)
		if err != nil {
			t.Fatal(err)
		}
		if d.Name != "Redirect-Realm" || d.Data.Type != datatype.DiameterIdentityType || d.Must != "" || d.May != "" || d.MustNot != "V" {
			t.Fatalf("Redirect-Realm: %+v", d)
		}
		m := baseMissingAnswer()
		m.Header.ApplicationID = app
		m.Header.CommandFlags |= ErrorFlag
		m.AVP[0].Data = datatype.Unsigned32(3011)
		m.AddAVP(NewAVP(620, 0, 0, datatype.DiameterIdentity("redirect.example")))
		if err := m.ValidateOutgoing(); err != nil {
			t.Fatal(err)
		}
		wire, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

// RFC 8581 §7.2 has two fixed members. An absent first member is a
// missing AVP (RFC 6733 §7.1.5), not a misplaced second member.
func TestMissingFirstFixedMember(t *testing.T) {
	group := NewAVP(avp.OCOLR, 0, 0, &GroupedAVP{AVP: []*AVP{NewAVP(avp.OCReportType, 0, 0, datatype.Enumerated(0))}})
	err := validateAVPs([]*AVP{group}, []*dict.Rule{{AVP: "AVP"}}, 0, dict.Default.Snapshot())
	if err == nil || err.ResultCode != MissingAVP || err.FailedAVP == nil || err.FailedAVP.Code != avp.OCOLR {
		t.Fatalf("missing first fixed member: %v", err)
	}
	members := err.FailedAVP.Data.(*GroupedAVP).AVP
	if len(members) != 1 || members[0].Code != avp.OCSequenceNumber {
		t.Fatalf("missing-member example: %v", members)
	}
}
