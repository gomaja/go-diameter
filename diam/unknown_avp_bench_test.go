package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// A peer can send any number of unrecognized vendor AVPs (RFC 6733 §4.1).
// Keep dictionary-miss bookkeeping out of this wire decoding cost.
func BenchmarkReadMessageUnknownAVPs(b *testing.B) {
	benchmarkReadMessageUnknownAVPs(b, avp.Vbit)
}

func BenchmarkReadMessageUnknownMandatoryAVPs(b *testing.B) {
	benchmarkReadMessageUnknownAVPs(b, avp.Vbit|avp.Mbit)
}

func benchmarkReadMessageUnknownAVPs(b *testing.B, flags uint8) {
	m := NewRequest(272, 4, dict.Default)
	m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	for code := uint32(70001); code <= 70010; code++ {
		m.AddAVP(NewAVP(code, flags, 10415, datatype.OctetString("payload!")))
	}
	wire, err := m.Serialize()
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			b.Fatal(err)
		}
		if len(got.AVP) != 11 {
			b.Fatal(len(got.AVP))
		}
	}
}
