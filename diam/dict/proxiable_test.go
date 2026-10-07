package dict

import "testing"

// TestBundledCommandsStateTheirPBit guards that every bundled command
// records the P bit of its request and answer Command Code Formats, which
// request construction and validation read. Only the hop-by-hop commands
// of RFC 6733 (CER/CEA §§5.3.1-5.3.2, DPR/DPA §§5.4.1-5.4.2, DWR/DWA
// §§5.5.1-5.5.2) lack PXY; every other bundled command's request is
// "REQ, PXY" and its answer "PXY" (RFC 6733 §§8.3-8.5, 9.7; RFC 7155 §3;
// RFC 8506 §§3.1-3.2; 3GPP TS 29.212 §5.6, TS 29.214 §5.6, TS 29.219 §5.6,
// TS 29.272 §7.2, TS 29.273 §8.2.2, TS 29.338 §§5.3.2, 6.3.2).
func TestBundledCommandsStateTheirPBit(t *testing.T) {
	hopByHop := map[uint32]bool{257: true, 280: true, 282: true}
	for _, b := range AllBundled() {
		for _, app := range bundledApps(t, b) {
			for _, cmd := range app.Command {
				want := app.ID != 0 || !hopByHop[cmd.Code]
				for _, side := range []struct {
					name string
					rule CommandRule
				}{{"request", cmd.Request}, {"answer", cmd.Answer}} {
					switch p := side.rule.Proxiable; {
					case p == nil:
						t.Errorf("%s: application %d %s %s states no P bit, want proxiable=%t", b, app.ID, cmd, side.name, want)
					case *p != want:
						t.Errorf("%s: application %d %s %s proxiable=%t, want %t", b, app.ID, cmd, side.name, *p, want)
					}
				}
			}
		}
	}
}
