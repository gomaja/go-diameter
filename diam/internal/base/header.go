package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
)

// FatalHeaderError identifies a lost frame detected before reading its body
// (RFC 6733 §3). Its version/length diagnosis precedes command-specific bits.
func FatalHeaderError(err *diam.MessageError) bool {
	return err != nil && err.Fatal && (err.ResultCode == diam.UnsupportedVersion || err.ResultCode == diam.InvalidMessageLength)
}

// ValidateHeader enforces RFC 6733 §§2.5, 3 and 3.2: CER/CEA, DWR/DWA
// and DPR/DPA carry Application-Id zero and their defined command flags.
// An inconsistent request header is 3008 (§7.1.3);
// answers are reported and discarded, never answered (§7).
func ValidateHeader(m *diam.Message) *diam.MessageError {
	if !IsCommand(m) {
		return nil
	}
	if m.Header.ApplicationID != 0 {
		return &diam.MessageError{ResultCode: diam.InvalidHDRBits, Err: fmt.Errorf("base command %d requires Application-Id zero (RFC 6733 §§2.5, 7.1.3)", m.Header.CommandCode)}
	}
	// RFC 6733 §§3, 3.2, 5.3.1–5.5.2: the normal base CCF clears P.
	// Generic E-bit answers instead copy P (§7.2). E is answer-only and
	// T request-only; ignore reserved bits.
	flags := m.Header.CommandFlags
	if flags&diam.ProxiableFlag != 0 && flags&diam.ErrorFlag == 0 || flags&diam.RequestFlag != 0 && flags&diam.ErrorFlag != 0 || flags&diam.RequestFlag == 0 && flags&diam.RetransmittedFlag != 0 {
		return &diam.MessageError{ResultCode: diam.InvalidHDRBits, Err: fmt.Errorf("invalid base command flags (RFC 6733 §§3, 3.2)")}
	}
	return nil
}
