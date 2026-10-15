package diam

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §§7.1.4–7.2 permit permanent errors with the generic error
// grammar on receipt. Our sending policy continues to reserve E for 3xxx.
func TestValidationReceivedErrorClasses(t *testing.T) {
	for _, code := range []uint32{999, 1000, 1999, 2000, 2999, 3000, 3999, 4000, 4999, 5000, 5012, 5999, 6000} {
		for _, p := range []uint8{0, ProxiableFlag} {
			t.Run(fmt.Sprintf("%d/P=%t", code, p != 0), func(t *testing.T) {
				m := NewMessage(DeviceWatchdog, ErrorFlag|p, 0, 1, 2, dict.Default)
				m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(code)))
				m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example.net")))
				m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
				valid := code >= 3000 && code < 4000 || code >= 5000 && code < 6000
				if err := m.Validate(); (err == nil) != valid {
					t.Fatalf("received E-bit result %d: error=%v, valid=%t", code, err, valid)
				}
				if err := m.ValidateOutgoing(); (err == nil) != (code >= 3000 && code < 4000) {
					t.Fatalf("outgoing E-bit result %d changed policy: %v", code, err)
				}
			})
		}
	}
}
