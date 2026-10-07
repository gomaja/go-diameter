package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/validation"
)

// BuildErrorAnswer constructs RFC 6733 §§6.2 and 7 answers; Verified Errata
// 4808 and 4887 govern Failed-AVP and local Origin-Realm respectively.
func BuildErrorAnswer(request *diam.Message, cfg Settings, resultCode uint32, failedAVPs []*diam.AVP, protocolError bool) (*diam.Message, error) {
	answer := request.Answer(0)
	dictionary := answer.Dictionary()
	definitions := dictionary.Snapshot()
	// RFC 6733 §§7 and 7.2: application errors such as 5001 clear R and T
	// without E; protocol errors such as 3001 set E. Both copy only P.
	answer.Header.CommandFlags = request.Header.CommandFlags & diam.ProxiableFlag
	// RFC 6733 §2.5 requires zero Application-Id for every CEA/DWA/DPA,
	// including E-bit errors for invalid request headers (§7.1.3).
	if request.Header.CommandCode == diam.CapabilitiesExchange || request.Header.CommandCode == diam.DeviceWatchdog || request.Header.CommandCode == diam.DisconnectPeer {
		answer.Header.ApplicationID = 0
		if !protocolError {
			answer.Header.CommandFlags = 0
		}
	}
	if protocolError {
		answer.Header.CommandFlags |= diam.ErrorFlag
	}
	// RFC 6733 §8.3.2 places Result-Code before the Origin AVPs in RAA.
	if !protocolError {
		if _, err := answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode)); err != nil {
			return nil, fmt.Errorf("add Result-Code to Diameter answer: %w", err)
		}
	}

	if _, err := answer.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost); err != nil {
		return nil, fmt.Errorf("add Origin-Host to Diameter error answer: %w", err)
	}
	// RFC 6733 §6.2, Verified Erratum 4887 requires the local Origin-Realm.
	if _, err := answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm); err != nil {
		return nil, fmt.Errorf("add Origin-Realm to Diameter error answer: %w", err)
	}
	if protocolError {
		if _, err := answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode)); err != nil {
			return nil, fmt.Errorf("add Result-Code to Diameter error answer: %w", err)
		}
	}
	if cfg.OriginStateID != 0 {
		if _, err := answer.NewAVP(avp.OriginStateID, avp.Mbit, 0, cfg.OriginStateID); err != nil {
			return nil, fmt.Errorf("add Origin-State-Id to Diameter error answer: %w", err)
		}
	}
	if len(failedAVPs) != 0 {
		// RFC 6733 Section 7.5 and Verified Errata 4808 require one
		// Failed-AVP container; it may retain the Grouped hierarchy.
		failed := &diam.GroupedAVP{AVP: failedAVPs}
		if _, err := answer.NewAVP(avp.FailedAVP, avp.Mbit, 0, failed); err != nil {
			return nil, fmt.Errorf("add Failed-AVP to Diameter error answer: %w", err)
		}
	}
	if !protocolError && request.Header.CommandCode == diam.CapabilitiesExchange {
		// RFC 6733 §5.3.2: even a permanent-error CEA retains its required
		// local capability fields when E is clear.
		addresses := cfg.HostIPAddresses
		if len(addresses) == 0 && cfg.ResolveHostIPAddresses != nil {
			var err error
			addresses, err = cfg.ResolveHostIPAddresses()
			if err != nil {
				return nil, fmt.Errorf("find local addresses for error CEA: %w", err)
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("cannot build CEA without a local Host-IP-Address")
		}
		for _, address := range addresses {
			if _, err := answer.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address); err != nil {
				return nil, err
			}
		}
		if _, err := answer.NewAVP(avp.VendorID, avp.Mbit, 0, cfg.VendorID); err != nil {
			return nil, err
		}
		if _, err := answer.NewAVP(avp.ProductName, 0, 0, cfg.ProductName); err != nil {
			return nil, err
		}
	}
	// RFC 6733 §§7.2 and 8.3.2: copy Session-Id when the complete answer
	// still fits, and place it first for application-specific answers.
	validationOption := validation.WithoutSessionID()
	for _, sessionID := range request.AVP {
		// RFC 6733 §6.2 refers to the command's Session-Id, not one
		// nested in a Grouped AVP or retained as peer evidence.
		if sessionID == nil || sessionID.Code != avp.SessionID || sessionID.VendorID != 0 {
			continue
		}
		if _, ok := sessionID.Data.(datatype.UTF8String); !ok {
			break // Do not substitute a later duplicate for undecodable evidence (§7.5).
		}
		validationOption = validation.ErrorAnswer{}
		if answer.Len()+sessionID.Len() > diam.MaxMessageLength {
			break
		}
		copied := rebuildAnswerAVP(sessionID, answer.Header.ApplicationID, dictionary, definitions, 0)
		if copied == nil {
			continue
		}
		answer.InsertAVP(copied)
		break
	}
	// RFC 6733 §§3.2 and 7.1.5: permanent errors keep the application
	// answer grammar. If the request omitted a field also required in that
	// answer, use the dictionary's zero-filled example for that field.
	if !protocolError {
		for i := 0; i < 32; i++ {
			validationErr := answer.ValidateErrorAnswer(validationOption)
			if validationErr == nil {
				break
			}
			if validationErr.ResultCode != diam.MissingAVP || validationErr.FailedAVP == nil {
				return nil, fmt.Errorf("cannot form valid Diameter error answer: %w", validationErr)
			}
			missing := validationErr.FailedAVP
			synthesized := true
			// RFC 8506 §3.2 requires the CCA's application and request
			// identifiers. Reuse matching request values before falling back
			// to RFC 6733 §7.5's zero-filled missing-AVP example.
			for _, received := range request.AVP {
				if received != nil && received.Code == missing.Code && received.VendorID == missing.VendorID && received.Data != nil {
					if rebuilt := rebuildAnswerAVP(received, answer.Header.ApplicationID, dictionary, definitions, 0); rebuilt != nil {
						missing = rebuilt
						synthesized = false
						break
					}
				}
			}
			// RFC 6733 §6.11: a missing VSAI needs one application-ID
			// alternative, not two independent optional members. The header
			// supplies the application even when decoding stopped before VSAI.
			if missing.Code == avp.VendorSpecificApplicationID && missing.VendorID == 0 {
				if group, ok := missing.Data.(*diam.GroupedAVP); ok && group != nil {
					if synthesized {
						if app, err := dictionary.App(answer.Header.ApplicationID); err == nil {
							for _, child := range group.AVP {
								if child != nil && child.Code == avp.VendorID && child.VendorID == 0 {
									child.Data = datatype.Unsigned32(app.ApplicationVendor())
								}
							}
						}
					}
					choice := false
					for _, child := range group.AVP {
						if child != nil && child.VendorID == 0 && (child.Code == avp.AuthApplicationID || child.Code == avp.AcctApplicationID) {
							choice = true
						}
					}
					if !choice {
						code := uint32(avp.AuthApplicationID)
						if app, err := dictionary.App(answer.Header.ApplicationID); err == nil && app.Type == "acct" {
							code = avp.AcctApplicationID
						}
						group.AVP = append(group.AVP, diam.NewAVP(code, avp.Mbit, 0, datatype.Unsigned32(answer.Header.ApplicationID)))
					}
				}
			}
			answer.AddAVP(missing)
			if i == 31 {
				return nil, fmt.Errorf("too many missing AVPs in Diameter error answer")
			}
		}
	}
	if validationErr := answer.ValidateErrorAnswer(validationOption); validationErr != nil {
		return nil, fmt.Errorf("cannot form valid Diameter error answer: %w", validationErr)
	}

	return answer, nil
}
