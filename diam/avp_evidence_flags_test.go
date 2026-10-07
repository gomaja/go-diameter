package diam

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 (October 2012) §7.5: Failed-AVP retains received header bits,
// including an invalid V bit paired with Vendor-Id 0 (§4.1.1).
func TestFailedAVPPreservesReceivedVendorFlag(t *testing.T) {
	for _, nested := range []bool{false, true} {
		bad := &AVP{Code: avp.AuthApplicationID, Flags: avp.Vbit | avp.Mbit, Data: datatype.Unknown{1, 2}}
		if nested {
			bad = &AVP{Code: avp.ProxyInfo, Flags: avp.Vbit | avp.Mbit, Data: &GroupedAVP{AVP: []*AVP{bad}}}
		}
		m := NewRequest(272, 4, dict.Default)
		m.AddAVP(bad)
		wire, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		_, err = ReadMessage(bytes.NewReader(wire), dict.Default)
		var failure *MessageError
		if !errors.As(err, &failure) {
			t.Fatalf("ReadMessage = %v, want MessageError", err)
		}
		a := failure.FailedAVP
		for a != nil {
			if a.Flags != avp.Vbit|avp.Mbit || a.VendorID != 0 || a.Length != 12+a.Data.Len() {
				t.Errorf("nested=%v: flags=%x vendor=%d length=%d", nested, a.Flags, a.VendorID, a.Length)
			}
			if group, ok := a.Data.(*GroupedAVP); ok {
				a = group.AVP[0]
			} else {
				a = nil
			}
		}
	}
}
