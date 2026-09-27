package diam

import (
	"bytes"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

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
