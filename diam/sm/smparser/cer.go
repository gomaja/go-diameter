// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package smparser

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
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
	parsed := &base.CER{
		HostIPAddresses:             cer.HostIPAddresses,
		OriginHost:                  cer.OriginHost,
		OriginRealm:                 cer.OriginRealm,
		OriginStateID:               cer.OriginStateID,
		InbandSecurityID:            cer.InbandSecurityID,
		AcctApplicationID:           cer.AcctApplicationID,
		AuthApplicationID:           cer.AuthApplicationID,
		VendorSpecificApplicationID: cer.VendorSpecificApplicationID,
	}
	failedAVP, err = parsed.Parse(m, base.ParseOptions{Role: base.Role(options.Role), TLS: options.TLS, Dictionary: options.Dictionary, LocalApplications: options.LocalApplications})
	cer.HostIPAddresses = parsed.HostIPAddresses
	cer.OriginHost = parsed.OriginHost
	cer.OriginRealm = parsed.OriginRealm
	cer.OriginStateID = parsed.OriginStateID
	cer.InbandSecurityID = parsed.InbandSecurityID
	cer.AcctApplicationID = parsed.AcctApplicationID
	cer.AuthApplicationID = parsed.AuthApplicationID
	cer.VendorSpecificApplicationID = parsed.VendorSpecificApplicationID
	if err == nil {
		cer.appID = parsed.Applications()
	}
	return failedAVP, adaptError(err)
}

// Applications return a list of supported Application IDs.
func (cer *CER) Applications() []uint32 {
	return cer.appID
}

// Clone returns an independent copy of the parsed CER, including AVPs and
// the application list used by peer metadata.
func (cer *CER) Clone() *CER {
	if cer == nil {
		return nil
	}
	copy := *cer
	copy.HostIPAddresses = base.CloneAddresses(cer.HostIPAddresses)
	copy.appID = append([]uint32(nil), cer.appID...)
	copy.OriginStateID = base.CloneAVP(cer.OriginStateID)
	copy.InbandSecurityID = base.CloneAVP(cer.InbandSecurityID)
	copy.AcctApplicationID = base.CloneAVPs(cer.AcctApplicationID)
	copy.AuthApplicationID = base.CloneAVPs(cer.AuthApplicationID)
	copy.VendorSpecificApplicationID = base.CloneAVPs(cer.VendorSpecificApplicationID)
	return &copy
}
