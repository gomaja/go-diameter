package diam

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// 3GPP TS 29.273 V19.2.0 §9.2 and TS 29.061 V20.1.0 §16.4.7.
func TestSWxDictionaryClosureWire(t *testing.T) {
	const appID = 16777265
	for _, tc := range []struct {
		name     string
		code     uint32
		vendor   uint32
		typeName string
	}{
		{"TGPP-Charging-Characteristics", 13, 10415, "UTF8String"},
		{"Feature-List", 630, 10415, "Unsigned32"},
		{"Feature-List-ID", 629, 10415, "Unsigned32"},
		{"IMEI", 1402, 10415, "UTF8String"},
		{"MIP-Home-Agent-Address", 334, 0, "Address"},
		{"MIP-Home-Agent-Host", 348, 0, "Grouped"},
		{"MIP6-Home-Link-Prefix", 125, 0, "OctetString"},
		{"Software-Version", 1403, 10415, "UTF8String"},
		{"3GPP2-MEID", 1471, 10415, "OctetString"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(appID, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != tc.vendor || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(265, appID, dict.Default)
			if tc.name == "MIP-Home-Agent-Address" {
				msg.AddAVP(NewAVP(d.Code, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))))
			} else {
				msg.AddAVP(smsAVP(t, appID, tc.name))
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			got, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", got.DecodeErr)
			}
		})
	}
}

// 3GPP TS 29.219 V19.0.0 §5.3.1 and RFC 8506 §8.
func TestSyDictionaryClosureWire(t *testing.T) {
	const appID = 16777302
	for _, tc := range []struct {
		name     string
		code     uint32
		vendor   uint32
		typeName string
	}{
		{"Policy-Counter-Identifier", 2901, 10415, "UTF8String"},
		{"Service-Information", 873, 10415, "Grouped"},
		{"Subscription-Id", 443, 0, "Grouped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(appID, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != tc.vendor || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(8388635, appID, dict.Default)
			msg.AddAVP(smsAVP(t, appID, tc.name))
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			got, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", got.DecodeErr)
			}
		})
	}
}

// 3GPP TS 29.214 V20.0.0 §5.4 and TS 29.212 V20.0.0 §§5.3.138-139.
func TestRxDictionaryClosureWire(t *testing.T) {
	const appID = 16777236
	for _, tc := range []struct {
		name     string
		code     uint32
		vendor   uint32
		typeName string
	}{
		{"Max-PLR-DL", 2852, 10415, "Unsigned32"},
		{"Max-PLR-UL", 2853, 10415, "Unsigned32"},
		{"TGPP-MS-TimeZone", 23, 10415, "OctetString"},
		{"TGPP-SGSN-MCC-MNC", 18, 10415, "UTF8String"},
		{"TGPP-User-Location-Info", 22, 10415, "OctetString"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(appID, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != tc.vendor || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(265, appID, dict.Default)
			msg.AddAVP(smsAVP(t, appID, tc.name))
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			got, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", got.DecodeErr)
			}
		})
	}
}

// 3GPP TS 32.299 V19.0.0 §§7.2, 7.3, 7.4 and the defining documents
// cited beside the XML definitions.
func TestChargingDictionaryClosureWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     uint32
		vendor   uint32
		typeName string
	}{
		{"Application-Port-Identifier", 3010, 10415, "Unsigned32"},
		{"Conditional-APN-Aggregate-Max-Bitrate", 2818, 10415, "Grouped"},
		{"DCD-Information", 2115, 10415, "Grouped"},
		{"Flow-Number", 509, 10415, "Unsigned32"},
		{"IM-Information", 2110, 10415, "Grouped"},
		{"Logical-Access-ID", 302, 13019, "OctetString"},
		{"Media-Component-Number", 518, 10415, "Unsigned32"},
		{"Physical-Access-ID", 313, 13019, "UTF8String"},
		{"Presence-Reporting-Area-Elements-List", 2820, 10415, "OctetString"},
		{"Service-Generic-Information", 1256, 10415, "Grouped"},
		{"3GPP2-BSID", 9010, 5535, "UTF8String"},
		{"3GPP2-MEID", 1471, 10415, "OctetString"},
		{"MSC-Number", 2403, 10415, "OctetString"},
		{"SGSN-Name", 2409, 10415, "DiameterIdentity"},
		{"SGSN-Realm", 2410, 10415, "DiameterIdentity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(4, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != tc.vendor || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(CreditControl, 4, dict.Default)
			msg.AddAVP(smsAVP(t, 4, tc.name))
			wire, err := msg.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || got.DecodeErr != nil {
				t.Fatalf("decode: %v, %v", err, got.DecodeErr)
			}
			if got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("type changed: %T -> %T", msg.AVP[0].Data, got.AVP[0].Data)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			fromConn, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if fromConn.DecodeErr != nil || len(fromConn.AVP) != 1 || fromConn.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", fromConn.DecodeErr)
			}
		})
	}
}

// RFC 7155 §§3, 4.1.1, 4.2, 4.4.9 and Verified Errata 5995, 6119.
func TestNASDictionaryClosureWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     uint32
		typeName string
	}{
		{"Connect-Info", 77, "UTF8String"},
		{"NAS-IP-Address", 4, "OctetString"},
		{"NAS-IPv6-Address", 95, "OctetString"},
		{"NAS-Identifier", 32, "UTF8String"},
		{"Origin-AAA-Protocol", 408, "Enumerated"},
		{"QoS-Filter-Rule", 407, "QoSFilterRule"},
		{"State", 24, "OctetString"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(1, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != 0 || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(265, 1, dict.Default)
			if tc.name == "QoS-Filter-Rule" {
				msg.AddAVP(NewAVP(d.Code, avp.Mbit, 0, datatype.QoSFilterRule("permit in ip from any to any")))
			} else {
				msg.AddAVP(smsAVP(t, 1, tc.name))
			}
			wire, err := msg.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("decode: %v", got.DecodeErr)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			fromConn, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if fromConn.DecodeErr != nil || len(fromConn.AVP) != 1 || fromConn.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", fromConn.DecodeErr)
			}
		})
	}
}

// 3GPP TS 29.272 V19.5.0 §§7.3.47, 7.3.83, 7.3.106-116, 7.3.156,
// 7.3.184, 7.3.196, 7.3.199, with reused AVPs from TS 29.273 and 29.336.
func TestS6aDictionaryClosureWire(t *testing.T) {
	const appID = 16777251
	for _, tc := range []struct {
		name     string
		code     uint32
		typeName string
	}{
		{"Alert-Reason", 1434, "Enumerated"},
		{"EPS-Location-Information", 1496, "Grouped"},
		{"EPS-User-State", 1495, "Grouped"},
		{"Emergency-Services", 1538, "Unsigned32"},
		{"IDA-Flags", 1441, "Unsigned32"},
		{"IMS-Voice-Over-PS-Sessions-Supported", 1492, "Enumerated"},
		{"Last-UE-Activity-Time", 1494, "Time"},
		{"Local-Time-Zone", 1649, "Grouped"},
		{"Maximum-UE-Availability-Time", 3329, "Time"},
		{"Monitoring-Event-Config-Status", 3142, "Grouped"},
		{"Monitoring-Event-Report", 3123, "Grouped"},
		{"Reset-ID", 1670, "OctetString"},
		{"Supported-Services", 3143, "Grouped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := dict.Default.FindAVP(appID, tc.name)
			if err != nil || d.Code != tc.code || d.VendorID != 10415 || d.Data.TypeName != tc.typeName {
				t.Fatalf("definition: %v, %v", d, err)
			}
			msg := NewRequest(319, appID, dict.Default)
			msg.AddAVP(smsAVP(t, appID, tc.name))
			wire, err := msg.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if got.DecodeErr != nil || len(got.AVP) != 1 || got.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("decode: %v", got.DecodeErr)
			}
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { _, e := msg.WriteTo(left); done <- e }()
			fromConn, err := ReadMessage(right, dict.Default)
			_ = left.Close()
			_ = right.Close()
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if fromConn.DecodeErr != nil || len(fromConn.AVP) != 1 || fromConn.AVP[0].Data.Type() != msg.AVP[0].Data.Type() {
				t.Fatalf("connection decode: %v", fromConn.DecodeErr)
			}
		})
	}
}
