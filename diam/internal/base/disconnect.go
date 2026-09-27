package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// ValidateDPR enforces the required single AVPs of RFC 6733 §5.4.1.
func ValidateDPR(m *diam.Message) (uint32, error) {
	if m.Header.ApplicationID != 0 || m.Header.CommandCode != diam.DisconnectPeer || m.Header.CommandFlags&diam.RequestFlag == 0 {
		return 0, fmt.Errorf("invalid DPR header")
	}
	var host, realm, cause int
	var value uint32
	for _, a := range m.AVP {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case avp.OriginHost:
			host++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPR Origin-Host")
			}
		case avp.OriginRealm:
			realm++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPR Origin-Realm")
			}
		case avp.DisconnectCause:
			cause++
			v, ok := a.Data.(datatype.Enumerated)
			if !ok || v < 0 || v > 2 {
				return 0, fmt.Errorf("invalid DPR Disconnect-Cause")
			}
			value = uint32(v)
		}
	}
	if host != 1 || realm != 1 || cause != 1 {
		return 0, fmt.Errorf("DPR requires one Origin-Host, Origin-Realm and Disconnect-Cause")
	}
	return value, nil
}

// ValidateDPA enforces the required single AVPs of RFC 6733 §5.4.2.
func ValidateDPA(m *diam.Message) (uint32, error) {
	if m.Header.ApplicationID != 0 || m.Header.CommandCode != diam.DisconnectPeer || m.Header.CommandFlags&diam.RequestFlag != 0 {
		return 0, fmt.Errorf("invalid DPA header")
	}
	var host, realm, result int
	var code uint32
	for _, a := range m.AVP {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case avp.OriginHost:
			host++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPA Origin-Host")
			}
		case avp.OriginRealm:
			realm++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPA Origin-Realm")
			}
		case avp.ResultCode:
			result++
			v, ok := a.Data.(datatype.Unsigned32)
			if !ok {
				return 0, fmt.Errorf("invalid DPA Result-Code")
			}
			code = uint32(v)
		}
	}
	if host != 1 || realm != 1 || result != 1 {
		return 0, fmt.Errorf("DPA requires one Result-Code, Origin-Host and Origin-Realm")
	}
	return code, nil
}
