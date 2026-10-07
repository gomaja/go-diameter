package base_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 6733 §6.2: an undecodable first Session-Id is not replaced by a duplicate.
func TestErrorAnswerUsesFirstSessionID(t *testing.T) {
	r := diam.NewRequest(diam.SessionTermination, 0, dict.Default)
	r.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.Unknown{}))
	r.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("later")))
	a, err := base.BuildErrorAnswer(r, fixtureSettings(), diam.InvalidAVPLength, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.FindAVPsWithPath(diam.AVPRef{Code: avp.SessionID})) != 0 {
		t.Fatal("copied later duplicate")
	}
}

// RFC 6733 §6.11: the synthesized VSAI identifies the application's vendor.
func TestErrorAnswerSynthesizedVSAIVendor(t *testing.T) {
	for _, tc := range []struct{ app, command uint32 }{{16777216, 300}, {16777265, 303}} {
		r := diam.NewMessage(tc.command, diam.RequestFlag|diam.ProxiableFlag, tc.app, 1, 2, dict.Default)
		a, err := base.BuildErrorAnswer(r, fixtureSettings(), diam.MissingAVP, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		got := a.FindAVPsWithPath(diam.AVPRef{Code: avp.VendorSpecificApplicationID}, diam.AVPRef{Code: avp.VendorID})
		if len(got) != 1 || got[0].Data != datatype.Unsigned32(10415) {
			t.Fatalf("app %d vendor: %v", tc.app, got)
		}
	}
}

// A base builder is an Answer caller and must not append a second proxy copy.
func TestErrorAnswerCallerCopiesProxyInfoOnce(t *testing.T) {
	r := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	r.AddAVP(diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")), diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("state"))}}))
	a, err := base.BuildDWA(r, fixtureSettings())
	if err != nil {
		t.Fatal(err)
	}
	if got := a.FindAVPsWithPath(diam.AVPRef{Code: avp.ProxyInfo}); len(got) != 1 {
		t.Fatalf("echo count %d", len(got))
	}
}

// RFC 6733 §6.2 refers to top-level Session-Id, not a nested evidence member.
func TestErrorAnswerIgnoresNestedSessionID(t *testing.T) {
	r := diam.NewRequest(diam.SessionTermination, 0, dict.Default)
	r.AddAVP(diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("nested"))}}))
	a, err := base.BuildErrorAnswer(r, fixtureSettings(), diam.MissingAVP, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.FindAVPsWithPath(diam.AVPRef{Code: avp.SessionID}); len(got) != 0 {
		t.Fatal("nested Session-Id became command Session-Id")
	}
}

// Unknown extension types retain their bytes without retaining caller storage.
func TestErrorAnswerProxyInfoExtensionStorage(t *testing.T) {
	payload := privatePayload{1, 2, 3, 4}
	r := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	r.AddAVP(diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(999999, 0, 0, payload)}}))
	a := r.Answer(diam.Success)
	echo := a.FindAVPsWithPath(diam.AVPRef{Code: avp.ProxyInfo})[0].Data.(*diam.GroupedAVP)
	data := echo.AVP[0].Data.(datatype.Unknown)
	if string(data) != string(payload) {
		t.Fatal("extension changed")
	}
	data[0] = 9
	if payload[0] != 1 {
		t.Fatal("extension storage shared")
	}
}

// RFC 6733 §6.11: a request's VSAI retains its vendor; only synthesized
// groups use the application's dictionary vendor.
func TestErrorAnswerKeepsRequestVSAIVendor(t *testing.T) {
	for _, tc := range []struct{ app, command uint32 }{{16777216, 300}, {16777265, 303}} {
		r := diam.NewMessage(tc.command, diam.RequestFlag|diam.ProxiableFlag, tc.app, 1, 2, dict.Default)
		r.AddAVP(diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(424242)),
			diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(tc.app)),
		}}))
		a, err := base.BuildErrorAnswer(r, fixtureSettings(), diam.MissingAVP, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		vendors := a.FindAVPsWithPath(diam.AVPRef{Code: avp.VendorSpecificApplicationID}, diam.AVPRef{Code: avp.VendorID})
		if len(vendors) != 1 || vendors[0].Data != datatype.Unsigned32(424242) {
			t.Fatalf("app %d: request vendor replaced: %v", tc.app, vendors)
		}
	}
}
