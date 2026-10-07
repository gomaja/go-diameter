package diam

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 (October 2012) §4.1: an unknown identity must retain its own
// bytes and vendor; a dictionary lookup miss is not a malformed payload.
func TestLookupMissPreservesUnknownWirePayload(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/nested=%t", strict, nested), func(t *testing.T) {
				p := dict.New(dict.Base)
				p.SetStrict(strict)
				m := NewRequest(272, 4, p)
				items := []*AVP{
					NewAVP(70001, 0, 0, datatype.Unknown{1, 2, 3}),
					NewAVP(70001, avp.Vbit|avp.Mbit, 10415, datatype.Unknown{4, 5, 6, 7, 8}),
					NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")),
				}
				if nested {
					m.AddAVP(NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{AVP: items}))
				} else {
					for _, a := range items {
						m.AddAVP(a)
					}
				}
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := ReadMessage(bytes.NewReader(wire), p)
				if err != nil {
					t.Fatalf("ReadMessage unknown identity: %v", err)
				}
				if decoded.DecodeErr != nil {
					t.Fatalf("unknown identity set DecodeErr: %v", decoded.DecodeErr)
				}
				got := decoded.AVP
				if nested {
					g, ok := got[0].Data.(*GroupedAVP)
					if !ok {
						t.Fatalf("group = %T", got[0].Data)
					}
					got = g.AVP
				}
				if len(got) != len(items) {
					t.Fatalf("AVP count = %d", len(got))
				}
				for i := 0; i < 2; i++ {
					raw, ok := got[i].Data.(datatype.Unknown)
					if !ok || !bytes.Equal(raw, items[i].Data.(datatype.Unknown)) || got[i].Code != items[i].Code || got[i].VendorID != items[i].VendorID {
						t.Errorf("AVP %d = %v; want %v", i, got[i], items[i])
					}
				}
				again, err := decoded.Serialize()
				if err != nil || !bytes.Equal(again, wire) {
					t.Fatalf("wire changed: %x, %v; want %x", again, err, wire)
				}
			})
		}
	}
}
