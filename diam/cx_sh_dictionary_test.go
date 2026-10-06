package diam

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// TS 29.229 V19.1.0 §§6.1, 6.3; TS 29.329 V19.1.0 §§6.1, 6.3.
func TestCxShGeneratedConstants(t *testing.T) {
	for _, tc := range []struct{ got, want uint32 }{
		{TGPP_CX_APP_ID, 16777216}, {TGPP_SH_APP_ID, 16777217},
		{UserAuthorization, 300}, {ServerAssignment, 301}, {LocationInfo, 302},
		{MultimediaAuth, 303}, {RegistrationTermination, 304}, {PushProfile, 305},
		{UserData, 306}, {ProfileUpdate, 307}, {SubscribeNotifications, 308}, {PushNotification, 309},
		{avp.UserData, 606}, {avp.ShUserData, 702}, {avp.OCRegTimerExt, 667},
	} {
		if tc.got != tc.want {
			t.Errorf("constant = %d, want %d", tc.got, tc.want)
		}
	}
	for _, tc := range []struct{ got, want string }{
		{UAR, "UAR"}, {UAA, "UAA"}, {SAR, "SAR"}, {SAA, "SAA"}, {LIR, "LIR"}, {LIA, "LIA"},
		{MAR, "MAR"}, {MAA, "MAA"}, {RTR, "RTR"}, {RTA, "RTA"}, {PPR, "PPR"}, {PPA, "PPA"},
		{UDR, "UDR"}, {UDA, "UDA"}, {PUR, "PUR"}, {PUA, "PUA"}, {SNR, "SNR"}, {SNA, "SNA"}, {PNR, "PNR"}, {PNA, "PNA"},
	} {
		if tc.got != tc.want {
			t.Errorf("short name = %s, want %s", tc.got, tc.want)
		}
	}
}

func TestCxShCommandRoundTrip(t *testing.T) {
	for code := uint32(300); code <= 309; code++ {
		app := uint32(16777216)
		if code >= 306 {
			app = 16777217
		}
		for _, request := range []bool{true, false} {
			for _, full := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/request=%t/full=%t", code, request, full), func(t *testing.T) {
					msg := cxShMessage(t, app, code, request, full)
					if err := msg.Validate(); err != nil {
						t.Fatal(err)
					}
					wire, err := msg.Serialize()
					if err != nil {
						t.Fatal(err)
					}
					got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
					if err != nil {
						t.Fatal(err)
					}
					cxShCheckDecoded(t, msg, got, wire)
					left, right := net.Pipe()
					defer func() { _ = left.Close(); _ = right.Close() }()
					if err := left.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if err := right.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { _, e := msg.WriteTo(left); done <- e }()
					got, err = ReadMessage(right, dict.Default)
					if err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					cxShCheckDecoded(t, msg, got, wire)
				})
			}
		}
	}
}

func cxShCheckDecoded(t *testing.T, want, got *Message, wire []byte) {
	t.Helper()
	if got.DecodeErr != nil {
		t.Fatal(got.DecodeErr)
	}
	if *got.Header != *want.Header {
		t.Fatalf("header changed: %+v -> %+v", want.Header, got.Header)
	}
	var check func([]*AVP, []*AVP)
	check = func(a, b []*AVP) {
		if len(a) != len(b) {
			t.Fatalf("AVP count %d -> %d", len(a), len(b))
		}
		for i := range a {
			if a[i].Code != b[i].Code || a[i].VendorID != b[i].VendorID || a[i].Flags != b[i].Flags || a[i].Data.Type() != b[i].Data.Type() {
				t.Fatalf("AVP changed: %v -> %v", a[i], b[i])
			}
			if g, ok := a[i].Data.(*GroupedAVP); ok {
				other, ok := b[i].Data.(*GroupedAVP)
				if !ok {
					t.Fatalf("group decoded as %T", b[i].Data)
				}
				check(g.AVP, other.AVP)
			}
		}
	}
	check(want.AVP, got.AVP)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := got.Serialize()
	if err != nil || !bytes.Equal(wire, encoded) {
		t.Fatalf("wire bytes changed: %v", err)
	}
}

// Every local AVP is exercised, including groups not named in a command CCF.
func TestCxShAVPRoundTrip(t *testing.T) {
	for _, appID := range []uint32{16777216, 16777217} {
		app, err := dict.Default.App(appID)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range app.AVP {
			t.Run(fmt.Sprintf("%d/%s", appID, d.Name), func(t *testing.T) {
				code := uint32(300)
				if appID == 16777217 {
					code = 306
				}
				msg := cxShMessage(t, appID, code, true, false)
				found := false
				for _, a := range msg.AVP {
					if a.Code == d.Code && a.VendorID == d.VendorID {
						found = true
					}
				}
				if !found {
					msg.AddAVP(cxShAVP(t, appID, d.Name, true))
				}
				wire, err := msg.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				cxShCheckDecoded(t, msg, got, wire)
			})
		}
	}
}

// CCF cardinality and fixed-prefix enforcement, including mandatory groups.
func TestCxShInvalidCommands(t *testing.T) {
	for code := uint32(300); code <= 309; code++ {
		app := uint32(16777216)
		if code >= 306 {
			app = 16777217
		}
		for _, request := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d/%t", code, request), func(t *testing.T) {
				msg := cxShMessage(t, app, code, request, false)
				for i, a := range msg.AVP {
					// Result-Code is chosen for a successful answer, but is optional in the CCF.
					if a.Code == avp.ResultCode && a.VendorID == 0 {
						continue
					}
					copyMsg := *msg
					copyMsg.AVP = append(append([]*AVP{}, msg.AVP[:i]...), msg.AVP[i+1:]...)
					if err := copyMsg.Validate(); err == nil {
						t.Errorf("accepted missing %d/%d", a.Code, a.VendorID)
					}
				}
				copyMsg := *msg
				copyMsg.Header = new(Header)
				*copyMsg.Header = *msg.Header
				copyMsg.Header.CommandFlags &^= ProxiableFlag
				if err := copyMsg.Validate(); err == nil || err.ResultCode != InvalidHDRBits {
					t.Errorf("accepted missing PXY: %v", err)
				}
				copyMsg = *msg
				copyMsg.AVP = append(append([]*AVP{}, msg.AVP...), msg.AVP[0])
				if err := copyMsg.Validate(); err == nil {
					t.Error("accepted duplicate Session-Id")
				}
				copyMsg = *msg
				copyMsg.AVP = append([]*AVP{}, msg.AVP...)
				copyMsg.AVP[0], copyMsg.AVP[1] = copyMsg.AVP[1], copyMsg.AVP[0]
				if err := copyMsg.Validate(); err == nil {
					t.Error("accepted displaced Session-Id")
				}
			})
		}
	}
}

// TS 29.329 V19.1.0 §§6.1.1, 6.1.3, 6.1.5: *{Data-Reference} is 1+.
func TestShRepeatedDataReferences(t *testing.T) {
	for _, code := range []uint32{306, 307, 308} {
		msg := cxShMessage(t, 16777217, code, true, false)
		msg.AddAVP(cxShAVP(t, 16777217, "Data-Reference", false))
		if err := msg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func cxShMessage(t testing.TB, app, code uint32, request, full bool) *Message {
	t.Helper()
	cmd, err := dict.Default.FindCommand(app, code)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(ProxiableFlag)
	rules := cmd.Answer.Rule
	if request {
		flags |= RequestFlag
		rules = cmd.Request.Rule
	}
	msg := NewMessage(code, flags, app, 0x12345678, 0x87654321, dict.Default)
	for _, r := range rules {
		if r.AVP == "AVP" || r.AVP == "Experimental-Result" || r.AVP == "Failed-AVP" {
			continue
		}
		if r.Required || full || (!request && r.AVP == "Result-Code") {
			msg.AddAVP(cxShAVP(t, app, r.AVP, full))
		}
	}
	return msg
}

func cxShAVP(t testing.TB, app uint32, name string, full bool) *AVP {
	t.Helper()
	d, err := dict.Default.FindAVP(app, name)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(0)
	if strings.Contains(d.Must, "M") {
		flags |= avp.Mbit
	}
	if d.VendorID != 0 {
		flags |= avp.Vbit
	}
	var value datatype.Type
	switch d.Data.TypeName {
	case "Grouped":
		g := &GroupedAVP{}
		switch name {
		case "Vendor-Specific-Application-Id":
			g.AddAVP(NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)))
			g.AddAVP(NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(app)))
		case "User-Identity":
			g.AddAVP(cxShAVP(t, app, "Public-Identity", false))
		default:
			for _, r := range d.Data.Rule {
				if r.AVP != "AVP" && (r.Required || full) {
					g.AddAVP(cxShAVP(t, app, r.AVP, full))
				}
			}
		}
		value = g
	case "Unsigned32":
		n := uint32(1)
		if name == "Result-Code" {
			n = 2001
		}
		value = datatype.Unsigned32(n)
	case "Unsigned64":
		value = datatype.Unsigned64(1)
	case "Enumerated":
		n := int32(0)
		if len(d.Data.Enum) > 0 {
			n = d.Data.Enum[0].Code
		}
		if name == "Auth-Session-State" {
			n = 1
		}
		value = datatype.Enumerated(n)
	case "OctetString":
		value = datatype.OctetString("payload")
	case "UTF8String":
		value = datatype.UTF8String("sip:user@example.net")
	case "DiameterIdentity":
		value = datatype.DiameterIdentity("node.example.net")
	case "DiameterURI":
		value = datatype.DiameterURI("aaa://node.example.net;transport=tcp;protocol=diameter")
	case "Address":
		value = datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	case "Time":
		value = datatype.Time(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	default:
		t.Fatalf("unsupported fixture type %s for %s", d.Data.TypeName, name)
	}
	return NewAVP(d.Code, flags, d.VendorID, value)
}

func FuzzCxShDictionaryMessages(f *testing.F) {
	for code := uint32(300); code <= 309; code++ {
		app := uint32(16777216)
		if code >= 306 {
			app = 16777217
		}
		for _, request := range []bool{true, false} {
			wire, err := cxShMessage(f, app, code, request, true).Serialize()
			if err != nil {
				f.Fatal(err)
			}
			f.Add(wire)
		}
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		msg, err := ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil || msg.DecodeErr != nil {
			return
		}
		// Re-encoding successfully decoded data must remain decodable, including
		// malformed inputs that the separate grammar validator rejects.
		_ = msg.Validate()
		encoded, err := msg.Serialize()
		if err != nil {
			return
		}
		again, err := ReadMessage(bytes.NewReader(encoded), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		if again.DecodeErr != nil {
			t.Fatal(again.DecodeErr)
		}
	})
}
