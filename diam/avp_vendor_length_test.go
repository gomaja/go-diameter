package diam

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 (October 2012) §§4.1, 4.1.1: V indicates the optional Vendor-Id field;
// AVP Length includes that field and excludes padding. Vendor-Id 0 is reserved.
func TestNewAVPVendorFlagAndLength(t *testing.T) {
	for _, vendor := range []uint32{0, 10415} {
		for _, flags := range []uint8{0, avp.Vbit, avp.Mbit | avp.Pbit, avp.Mbit | avp.Pbit | avp.Vbit} {
			for _, payload := range []string{"", "abcd", "abcde"} {
				t.Run(fmt.Sprintf("vendor=%d/flags=%x/bytes=%d", vendor, flags, len(payload)), func(t *testing.T) {
					wantFlags := flags &^ avp.Vbit
					header := 8
					if vendor != 0 {
						wantFlags |= avp.Vbit
						header = 12
					}
					wantLength := header + len(payload)
					m := NewRequest(272, 4, dict.Default)
					for _, makeAVP := range []func() *AVP{
						func() *AVP { return NewAVP(70001, flags, vendor, datatype.UTF8String(payload)) },
						func() *AVP {
							a, err := m.NewAVP(70001, flags, vendor, datatype.UTF8String(payload))
							if err != nil {
								t.Fatal(err)
							}
							return a
						},
					} {
						a := makeAVP()
						if a.Flags != wantFlags || a.Length != wantLength || a.Len() != (wantLength+3)&^3 {
							t.Errorf("flags/Length/Len = %x/%d/%d, want %x/%d/%d", a.Flags, a.Length, a.Len(), wantFlags, wantLength, (wantLength+3)&^3)
						}
						wire, err := a.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						gotLength := int(wire[5])<<16 | int(wire[6])<<8 | int(wire[7])
						if wire[4] != wantFlags || gotLength != wantLength || !bytes.Equal(wire[header:wantLength], []byte(payload)) {
							t.Errorf("bad wire %x", wire)
						}
						if vendor != 0 && binary.BigEndian.Uint32(wire[8:12]) != vendor {
							t.Errorf("wire vendor %x", wire[8:12])
						}
					}
				})
			}
		}
	}
	for _, tc := range []struct {
		name   string
		vendor uint32
		header int
	}{{"TGPP-GGSN-MCC-MNC", 10415, 12}, {"User-Name", 0, 8}} {
		for _, flags := range []uint8{0, avp.Vbit} {
			m := NewRequest(272, 4, dict.Default)
			a, err := m.NewAVPByName(tc.name, flags, datatype.UTF8String("abcd"))
			if err != nil {
				t.Fatal(err)
			}
			if a.VendorID != tc.vendor || (a.Flags&avp.Vbit != 0) != (tc.vendor != 0) || a.Length != tc.header+4 || a.Len() != tc.header+4 || int(m.Header.MessageLength) != HeaderLength+a.Len() {
				t.Errorf("%s flags=%x: AVP=%+v Length=%d Len=%d message=%d", tc.name, flags, a, a.Length, a.Len(), m.Header.MessageLength)
			}
		}
	}
}

func TestUnknownAVPDecodeAllocations(t *testing.T) {
	wire, err := NewAVP(70001, avp.Vbit, 10415, datatype.Unknown{1, 2, 3, 4}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	for _, strict := range []bool{false, true} {
		p := dict.New(dict.Base)
		p.SetStrict(strict)
		var got AVP
		count := testing.AllocsPerRun(100, func() {
			if err := got.DecodeFromBytes(wire, 4, p); err != nil {
				t.Fatal(err)
			}
		})
		// One owned payload and one interface box; no diagnostic/placeholder objects.
		if count > 2 {
			t.Errorf("strict=%v: unknown decode allocated %g times, want <=2", strict, count)
		}
		wire[12] = 9
		if !bytes.Equal(got.Data.(datatype.Unknown), []byte{1, 2, 3, 4}) {
			t.Fatal("decoded data aliases input")
		}
		wire[12] = 1
	}
}

func TestUnknownMandatoryPresenceDoesNotAllocate(t *testing.T) {
	a := NewAVP(70001, avp.Mbit|avp.Vbit, 10415, datatype.Unknown{1, 2, 3, 4})
	s := dict.Default.Snapshot()
	if n := testing.AllocsPerRun(100, func() {
		if unknownMandatoryHierarchy(a, 4, s) != a {
			t.Fatal("missing unknown mandatory AVP")
		}
	}); n != 0 {
		t.Errorf("unknown mandatory presence allocated %g times, want zero", n)
	}
}

func TestDecodeAVPResetsAbsentVendor(t *testing.T) {
	var reused AVP
	for _, vendor := range []uint32{10415, 0} {
		wire, err := NewAVP(70001, 0, vendor, datatype.Unknown{1, 2, 3, 4}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if err := reused.DecodeFromBytes(wire, 4, dict.Default); err != nil {
			t.Fatal(err)
		}
		if reused.VendorID != vendor {
			t.Errorf("decoded V=%t with vendor=%d, want %d", reused.Flags&avp.Vbit != 0, reused.VendorID, vendor)
		}
	}
}
