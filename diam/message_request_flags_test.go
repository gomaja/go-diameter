package diam

import (
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

// TestNewRequestSetsTheFlagsItsCommandRequires guards that NewRequest sets
// R, and P exactly when the request's Command Code Format carries PXY
// (RFC 6733 §§3, 3.2), as the dictionary's definition records it.
func TestNewRequestSetsTheFlagsItsCommandRequires(t *testing.T) {
	unstated, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := unstated.Load(strings.NewReader(`<diameter><application id="999">
<command code="999" name="Test" short="TE"><request><rule avp="Session-Id" required="true" max="1"/></request>
<answer><rule avp="Session-Id" required="true" max="1"/></answer></command>
<avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y"><data type="UTF8String"/></avp>
</application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	const rp = RequestFlag | ProxiableFlag
	for _, tc := range []struct {
		name       string
		cmd, app   uint32
		dictionary *dict.Parser
		want       uint8
	}{
		// RFC 8506 §3.1, 3GPP TS 29.272 §§7.2.3, 7.2.5, RFC 6733 §9.7.1.
		{"CCR", CreditControl, 4, dict.Default, rp},
		{"CCR, nil dictionary", CreditControl, 4, nil, rp},
		{"AIR", AuthenticationInformation, TGPP_S6A_APP_ID, dict.Default, rp},
		{"ULR", UpdateLocation, TGPP_S6A_APP_ID, dict.Default, rp},
		{"ACR", Accounting, 0, dict.Default, rp},
		// RFC 6733 §§5.3.1, 5.5.1, 5.4.1: hop-by-hop, not proxiable.
		{"CER", CapabilitiesExchange, 0, dict.Default, RequestFlag},
		{"DWR", DeviceWatchdog, 0, dict.Default, RequestFlag},
		{"DPR", DisconnectPeer, 0, dict.Default, RequestFlag},
		// Nothing tells NewRequest the P bit of these.
		{"command the dictionary does not define", 0xfedc, 999, dict.Default, RequestFlag},
		{"definition without a P bit", 999, 999, unstated, RequestFlag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewRequest(tc.cmd, tc.app, tc.dictionary)
			if got := m.Header.CommandFlags; got != tc.want {
				t.Fatalf("command flags = %#x, want %#x", got, tc.want)
			}
			// RFC 6733 §3: the Command Flags are the fifth header octet.
			b, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if b[4] != tc.want {
				t.Fatalf("command flags on the wire = %#x, want %#x", b[4], tc.want)
			}
		})
	}
}

// TestNewRequestPassesTheHeaderCheckOfEveryBundledCommand guards that the
// flags NewRequest sets for each bundled command are the ones
// Message.Validate requires: it rejects a P bit that disagrees with the
// command grammar with 3008 (RFC 6733 §7.1.3).
func TestNewRequestPassesTheHeaderCheckOfEveryBundledCommand(t *testing.T) {
	for _, app := range dict.Default.Apps() {
		for _, cmd := range app.Command {
			m := NewRequest(cmd.Code, app.ID, dict.Default)
			if err := m.Validate(); err != nil && err.ResultCode == InvalidHDRBits {
				t.Errorf("application %d %s: NewRequest flags %#x: %v", app.ID, cmd, m.Header.CommandFlags, err)
			}
			if p := cmd.Request.Proxiable; p != nil && (m.Header.CommandFlags&ProxiableFlag != 0) != *p {
				t.Errorf("application %d %s: NewRequest flags %#x, request proxiable=%t", app.ID, cmd, m.Header.CommandFlags, *p)
			}
		}
	}
}
