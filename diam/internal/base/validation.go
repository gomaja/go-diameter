package base

import (
	"fmt"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// Base grammar is a protocol requirement, independent of application dictionary
// overrides and opt-in application validation (RFC 6733 §§3.2, 5.3.1–5.5.2).
var grammarDictionary = sync.OnceValue(func() *dict.Parser {
	d, err := dict.New(dict.Base())
	if err != nil {
		panic(err)
	}
	return d
})

// IsCommand recognizes the three connection-level base command codes.
func IsCommand(m *diam.Message) bool {
	if m == nil || m.Header == nil {
		return false
	}
	switch m.Header.CommandCode {
	case diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer:
		return true
	}
	return false
}

// AnswerErrorKind keeps discarded base-answer diagnostics consistent across adapters.
func AnswerErrorKind(m *diam.Message) diam.ProtocolErrorKind {
	switch m.Header.CommandCode {
	case diam.DeviceWatchdog:
		return diam.ProtocolInvalidDWA
	case diam.DisconnectPeer:
		return diam.ProtocolInvalidDPA
	default:
		return diam.ProtocolCEARejected
	}
}

// ValidateMessage checks the six base messages, including the distinct E-bit
// grammar of RFC 6733 §7.2. Failed-AVP is evidence, never a new message to check
// (RFC 6733 §7.5; Verified Errata 4615, 4808).
func ValidateMessage(m *diam.Message) *diam.MessageError {
	if err := ValidateHeader(m); err != nil {
		return err
	}
	if !IsCommand(m) {
		return nil
	}
	canonical := grammarDictionary()
	message := diam.NewMessage(m.Header.CommandCode, m.Header.CommandFlags, 0, 1, 1, canonical)
	message.Header, message.AVP = m.Header, m.AVP
	if err := message.Validate(); err != nil {
		return &diam.MessageError{ResultCode: err.ResultCode, FailedAVP: err.FailedAVP, Err: err}
	}
	// RFC 6733 §§7.1.3, 7.2: protocol errors require E in both directions.
	if m.Header.CommandFlags&diam.RequestFlag == 0 && m.Header.CommandFlags&diam.ErrorFlag == 0 {
		for _, a := range m.AVP {
			if a.Code == avp.ResultCode && a.VendorID == 0 {
				if value, ok := a.Data.(datatype.Unsigned32); ok && value >= 3000 && value < 4000 {
					return &diam.MessageError{ResultCode: diam.InvalidHDRBits, Err: fmt.Errorf("3xxx result requires E bit (RFC 6733 §7.1.3)")}
				}
				break
			}
		}
	}
	return validateTypes(m.AVP, canonical.Snapshot())
}

func validateTypes(items []*diam.AVP, dictionary *dict.Snapshot) *diam.MessageError {
	for _, a := range items {
		definition, err := dictionary.FindAVP(0, a.Code, a.VendorID)
		if err != nil || a.Code == avp.FailedAVP && a.VendorID == 0 {
			continue
		}
		code := uint32(diam.InvalidAVPValue)
		invalid := a.Data == nil || a.Data.Type() != definition.Data.Type
		if definition.Data.Type == datatype.GroupedType {
			group, ok := a.Data.(*diam.GroupedAVP)
			invalid = !ok || group == nil
		}
		if a.Data != nil {
			switch definition.Data.Type {
			case datatype.Unsigned32Type, datatype.EnumeratedType:
				if a.Data.Len() != 4 {
					code, invalid = diam.InvalidAVPLength, true
				}
			case datatype.AddressType:
				if _, err := datatype.DecodeAddress(a.Data.Serialize()); err != nil {
					invalid = true
					if a.Data.Len() < 2 {
						code = diam.InvalidAVPLength
					}
				}
			case datatype.DiameterIdentityType:
				invalid = invalid || !validIdentity(a.Data.Serialize())
			case datatype.UTF8StringType:
				invalid = invalid || !utf8.Valid(a.Data.Serialize())
			}
		}
		// RFC 6733 §5.4.3 defines the three Disconnect-Cause values.
		if a.Code == avp.DisconnectCause && a.VendorID == 0 {
			if value, ok := a.Data.(datatype.Enumerated); ok {
				invalid = invalid || value < 0 || value > 2
			}
		}
		// RFC 6733 §5.3.6 prohibits zero even though Vendor-Id (§5.3.3)
		// itself permits zero for the IETF namespace.
		if a.Code == avp.SupportedVendorID && a.VendorID == 0 {
			if value, ok := a.Data.(datatype.Unsigned32); ok {
				invalid = invalid || value == 0
			}
		}
		if invalid {
			return &diam.MessageError{ResultCode: code, FailedAVP: a, Err: fmt.Errorf("invalid base %s data", definition.Name)}
		}
		if group, ok := a.Data.(*diam.GroupedAVP); ok {
			if group == nil {
				return &diam.MessageError{ResultCode: diam.InvalidAVPValue, FailedAVP: a, Err: fmt.Errorf("nil base Grouped AVP")}
			}
			if err := validateTypes(group.AVP, dictionary); err != nil {
				parent := *a
				parent.Data = &diam.GroupedAVP{AVP: []*diam.AVP{err.FailedAVP}}
				err.FailedAVP = &parent
				return err
			}
		}
	}
	return nil
}

// RFC 6733 §4.3.1 and Appendix D require ASCII FQDN/realm form. Accept
// case, numeric labels, A-labels and the optional final DNS root dot.
func validIdentity(name []byte) bool {
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	label := 0
	for i, c := range name {
		if c == '.' {
			if label == 0 || name[i-1] == '-' {
				return false
			}
			label = 0
			continue
		}
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		if !letter && !digit && (c != '-' || label == 0) {
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	return label > 0 && name[len(name)-1] != '-'
}

// RequestError is a shared rejection decision; the adapters retain ownership of
// reply delivery and connection closure.
type RequestError struct {
	Kind   diam.ProtocolErrorKind
	Code   uint32
	Failed []*diam.AVP
}

// SupportsApplication tests the connection's advertised application snapshot.
func SupportsApplication(applications []uint32, appID uint32) bool {
	return appID == 0 || slices.Contains(applications, appID) || slices.Contains(applications, uint32(0xffffffff))
}

// ValidateRequest preserves the configured application pipeline: advertised
// membership, unknown mandatory AVPs, then dictionary grammar. The ordering is
// policy; result codes and evidence follow RFC 6733 §§4.1, 7.1–7.5. Relay and
// redirect agents advertise 0xffffffff (§2.4) and do not reject unknown AVPs
// (§4.1). An unknown optional Grouped AVP is opaque to the decoder (§4.4).
func ValidateRequest(m *diam.Message, applications []uint32, validate, rejectUnknown bool, decodeErrors ...*diam.MessageError) *RequestError {
	if m.Header.CommandFlags&diam.RequestFlag == 0 {
		return nil
	}
	if validate && !SupportsApplication(applications, m.Header.ApplicationID) {
		return &RequestError{Kind: diam.ProtocolUnsupportedApplication, Code: diam.ApplicationUnsupported}
	}
	if rejectUnknown && !slices.Contains(applications, uint32(0xffffffff)) {
		if failed := m.UnknownMandatoryAVPs(); len(failed) != 0 {
			return &RequestError{Kind: diam.ProtocolUnsupportedAVP, Code: diam.AVPUnsupported, Failed: failed}
		}
	}
	if len(decodeErrors) != 0 && decodeErrors[0] != nil {
		err := decodeErrors[0]
		rejection := &RequestError{Kind: diam.ProtocolMalformedMessage, Code: err.ResultCode}
		if err.FailedAVP != nil {
			rejection.Failed = []*diam.AVP{err.FailedAVP}
		}
		return rejection
	}
	if validate {
		if err := m.Validate(); err != nil {
			rejection := &RequestError{Kind: diam.ProtocolInvalidRequest, Code: err.ResultCode}
			if err.FailedAVP != nil {
				rejection.Failed = []*diam.AVP{err.FailedAVP}
			}
			return rejection
		}
	}
	return nil
}
