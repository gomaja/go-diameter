package diam

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// 3GPP TS 29.338 V19.3.0 §§5.3.2.3-5.3.2.8, Table 5.3.2.2/1.
func TestSMSGeneratedConstants(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 §4.1, Tables 5.3.2.2/1 and 6.3.2.2/1.
	for _, tc := range []struct {
		name      string
		got, want uint32
	}{
		{"S6c application", TGPP_S6C_APP_ID, 16777312},
		{"SGd application", TGPP_SGD_APP_ID, 16777313},
		{"SRR/SRA", SendRoutingInfoforSM, 8388647},
		{"ALR/ALA", AlertServiceCentre, 8388648},
		{"RDR/RDA", ReportSMDeliveryStatus, 8388649},
		{"OFR/OFA", MOForwardShortMessage, 8388645},
		{"TFR/TFA", MTForwardShortMessage, 8388646},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestS6cMandatoryRoundTrip(t *testing.T) {
	for _, code := range []uint32{8388647, 8388648, 8388649} {
		for _, request := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d/request=%t", code, request), func(t *testing.T) { smsRoundTrip(t, 16777312, code, request) })
		}
	}
}

// 3GPP TS 29.338 V19.3.0 §§6.3.2.3-6.3.2.6, Table 6.3.2.2/1.
func TestSGdMandatoryRoundTrip(t *testing.T) {
	for _, code := range []uint32{8388645, 8388646} {
		for _, request := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d/request=%t", code, request), func(t *testing.T) { smsRoundTrip(t, 16777313, code, request) })
		}
	}
}

func TestSMSAVPTypesRoundTrip(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 Tables 5.3.3.1/1 and 6.3.3.1/1.
	app, err := dict.Default.App(16777312)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range app.AVP {
		t.Run(d.Name, func(t *testing.T) {
			m := NewRequest(8388647, 16777312, dict.Default)
			m.AddAVP(smsAVP(t, 16777312, d.Name))
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || got.DecodeErr != nil {
				t.Fatalf("decode: %v, %v", err, got.DecodeErr)
			}
			if got.AVP[0].Code != d.Code || got.AVP[0].Data.Type() != m.AVP[0].Data.Type() {
				t.Fatalf("AVP %s changed type or code", d.Name)
			}
			encoded, err := got.Serialize()
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("AVP %s changed bytes: %v", d.Name, err)
			}
		})
	}
}

func smsRoundTrip(t *testing.T, appid, code uint32, request bool) {
	t.Helper()
	command, err := dict.Default.FindCommand(appid, code)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(0)
	rules := command.Answer.Rule
	if request {
		flags = RequestFlag
		rules = command.Request.Rule
	}
	msg := NewMessage(code, flags, appid, 1, 2, dict.Default)
	for _, rule := range rules {
		if !rule.Required || rule.AVP == "AVP" {
			continue
		}
		a := smsAVP(t, appid, rule.AVP)
		msg.AddAVP(a)
	}
	// The SRR allows both subscriber identifiers; exercise their vendor scopes.
	if appid == 16777312 && code == 8388647 && request {
		msg.AddAVP(smsAVP(t, appid, "MSISDN"))
		msg.AddAVP(smsAVP(t, appid, "User-Name"))
	}
	wire, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if got.DecodeErr != nil {
		t.Fatal(got.DecodeErr)
	}
	if got.Header.ApplicationID != appid || got.Header.CommandCode != code || len(got.AVP) != len(msg.AVP) {
		t.Fatalf("round trip mismatch: %#v", got.Header)
	}
	for i, a := range got.AVP {
		if a.Code != msg.AVP[i].Code || a.VendorID != msg.AVP[i].VendorID || a.Data.Type() != msg.AVP[i].Data.Type() {
			t.Fatalf("AVP %d: got %v, want %v", i, a, msg.AVP[i])
		}
	}
	encoded, err := got.Serialize()
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("message changed bytes: %v", err)
	}
	// Drive the same bytes through the connection path.
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	done := make(chan error, 1)
	go func() { _, e := msg.WriteTo(left); done <- e }()
	networkGot, err := ReadMessage(right, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if networkGot.DecodeErr != nil || len(networkGot.AVP) != len(msg.AVP) {
		t.Fatalf("connection round trip: %v", networkGot.DecodeErr)
	}
}

func smsAVP(t *testing.T, appid uint32, name string) *AVP {
	t.Helper()
	d, err := dict.Default.FindAVPByName(appid, name)
	if err != nil {
		t.Fatal(err)
	}
	var flags uint8
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
		for _, rule := range d.Data.Rule {
			if rule.Required {
				g.AddAVP(smsAVP(t, appid, rule.AVP))
			}
		}
		if name == "User-Identifier" {
			g.AddAVP(smsAVP(t, appid, "User-Name"))
		}
		if name == "SM-Delivery-Outcome" {
			g.AddAVP(smsAVP(t, appid, "MME-SM-Delivery-Outcome"))
		}
		if name == "EPS-Location-Information" {
			g.AddAVP(smsAVP(t, appid, "MME-Location-Information"))
		}
		if name == "MME-Location-Information" {
			g.AddAVP(smsAVP(t, appid, "E-UTRAN-Cell-Global-Identity"))
		}
		if name == "SMSMI-Correlation-ID" {
			g.AddAVP(smsAVP(t, appid, "HSS-ID"))
		}
		value = g
	case "Unsigned32":
		value = datatype.Unsigned32(1)
	case "Enumerated":
		value = datatype.Enumerated(0)
	case "DiameterIdentity":
		value = datatype.DiameterIdentity("node.example")
	case "UTF8String":
		value = datatype.UTF8String("subscriber")
	case "OctetString":
		value = datatype.OctetString([]byte{0x21, 0x43})
	case "Time":
		value = datatype.Time(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	default:
		t.Fatalf("unsupported %s type %s", name, d.Data.TypeName)
	}
	return NewAVP(d.Code, flags, d.VendorID, value)
}
