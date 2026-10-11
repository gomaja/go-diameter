//go:build linux && !386

package sm

import "testing"

func TestAcceptedCERRenewalPolicyOnWireSCTP(t *testing.T) {
	requireSCTP(t)
	testAcceptedCERRenewalPolicyOnWire(t, "sctp")
}
