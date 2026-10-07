// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// CER is a Capabilities-Exchange-Request message.
// See RFC 6733 section 5.3.1 for details.
type CER struct {
	HostIPAddresses             []datatype.Address        `avp:"Host-IP-Address"`
	OriginHost                  datatype.DiameterIdentity `avp:"Origin-Host"`
	OriginRealm                 datatype.DiameterIdentity `avp:"Origin-Realm"`
	OriginStateID               *diam.AVP                 `avp:"Origin-State-Id"`
	InbandSecurityID            *diam.AVP                 `avp:"Inband-Security-Id"`
	AcctApplicationID           []*diam.AVP               `avp:"Acct-Application-Id"`
	AuthApplicationID           []*diam.AVP               `avp:"Auth-Application-Id"`
	VendorSpecificApplicationID []*diam.AVP               `avp:"Vendor-Specific-Application-Id"`
	appID                       []uint32                  // List of supported application IDs.
}

// ParseOptions selects the local capabilities used to validate a CER or CEA.
type ParseOptions struct {
	Role Role
	// TLS reports whether transport security is already established (RFC 6733 §6.10).
	TLS bool
	// Dictionary defaults to the message dictionary when nil (RFC 6733 §5.3).
	Dictionary *dict.Parser
	// LocalApplications overrides dictionary membership when non-nil.
	// An empty slice offers no applications; a peer relay offer still counts
	// as common (RFC 6733 §§2.4, 5.3).
	LocalApplications []uint32
}

// Parse decodes a CER and validates common security and applications
// (RFC 6733 §§5.3, 6.10). AVP errors identify the offending AVP.
func (cer *CER) Parse(m *diam.Message, options ParseOptions) (failedAVP *diam.AVP, err error) {
	if err := ValidateHeader(m); err != nil {
		return nil, err
	}
	// A non-strict dictionary retains an undecodable Address payload as
	// Unknown. Classify it before reflection requires datatype.Address, so
	// RFC 6733 §§4.3.1 and 7.1.5 can identify the original AVP in the
	// error answer (RFC 6733 §7.5, Verified Erratum 4615).
	for _, a := range m.AVP {
		if a.Code != avp.HostIPAddress || a.VendorID != 0 {
			continue
		}
		if _, raw := a.Data.(datatype.Unknown); raw {
			result := uint32(diam.InvalidAVPValue)
			if a.Data.Len() < 2 {
				result = diam.InvalidAVPLength
			}
			return a, &diam.MessageError{ResultCode: result, FailedAVP: a, Err: fmt.Errorf("Host-IP-Address is not a valid Address")}
		}
	}
	if err = m.Unmarshal(cer); err != nil {
		return nil, err
	}
	if err = cer.sanityCheck(); err != nil {
		var code uint32
		if err == ErrMissingOriginHost {
			code = avp.OriginHost
		} else {
			code = avp.OriginRealm
		}
		// RFC 6733 §7.1.5, Verified Erratum 4615: one Failed-AVP with a zero-valued example.
		failed := diam.NewAVP(code, avp.Mbit, 0, datatype.DiameterIdentity("\x00"))
		return failed, &diam.MessageError{ResultCode: diam.MissingAVP, FailedAVP: failed, Err: err}
	}
	// RFC 6733 §§5.3.1 and 6.10: the AVP may repeat, and omission
	// means NO_INBAND_SECURITY. Every present AVP must have four bytes.
	var offered, common bool
	for _, a := range m.AVP {
		if a.Code != avp.InbandSecurityID || a.VendorID != 0 {
			continue
		}
		offered = true
		v, ok := a.Data.(datatype.Unsigned32)
		if !ok {
			return a, &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: a, Err: fmt.Errorf("Inband-Security-Id must be Unsigned32")}
		}
		// RFC 6733 §6.10 defines only 0 and 1; §5.3 requires a common
		// mechanism even when the transport is already secured.
		common = common || v == 0 || v == 1 && options.TLS
	}
	if offered && !common {
		return nil, ErrNoCommonSecurity
	}
	app := &Application{
		AcctApplicationID:           cer.AcctApplicationID,
		AuthApplicationID:           cer.AuthApplicationID,
		VendorSpecificApplicationID: cer.VendorSpecificApplicationID,
	}
	dictionary := options.Dictionary
	if dictionary == nil {
		dictionary = m.Dictionary()
	}
	if failedAVP, err = app.ParseWithApplicationIDs(dictionary, options.Role, options.LocalApplications); err != nil {
		return failedAVP, err
	}
	cer.appID = app.ID()
	return nil, nil
}

// sanityCheck ensures mandatory AVPs are present.
func (cer *CER) sanityCheck() error {
	if len(cer.OriginHost) == 0 {
		return ErrMissingOriginHost
	}
	if len(cer.OriginRealm) == 0 {
		return ErrMissingOriginRealm
	}
	return nil
}

// Applications return a list of supported Application IDs.
func (cer *CER) Applications() []uint32 {
	return cer.appID
}
