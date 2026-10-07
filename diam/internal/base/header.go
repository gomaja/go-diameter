package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
)

// ValidateHeader enforces RFC 6733 §2.5: CER/CEA, DWR/DWA and DPR/DPA
// carry Application-Id zero. An inconsistent request header is 3008 (§7.1.3);
// answers are reported and discarded, never answered (§7).
func ValidateHeader(m *diam.Message) *diam.MessageError {
	if m == nil || m.Header == nil || m.Header.ApplicationID == 0 {
		return nil
	}
	switch m.Header.CommandCode {
	case diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer:
		return &diam.MessageError{ResultCode: diam.InvalidHDRBits, Err: fmt.Errorf("base command %d requires Application-Id zero (RFC 6733 §§2.5, 7.1.3)", m.Header.CommandCode)}
	}
	return nil
}
