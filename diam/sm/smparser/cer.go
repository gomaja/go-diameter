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

// Parse parses and validates the given message, and returns nil when
// all AVPs are ok, and all accounting or authentication applications
// in the CER match the applications in our dictionary. If one or more
// mandatory AVPs are missing, it returns a nil failedAVP and a proper
// error. If all mandatory AVPs are present but no common application
// is found, then it returns the failedAVP (with the application that
// we don't support in our dictionary) and an error. Another cause
// for error is the presence of Inband Security, we don't support that.
func (cer *CER) Parse(m *diam.Message, localRole Role) (failedAVP *diam.AVP, err error) {
	return cer.ParseWithSecurity(m, localRole, false)
}

// ParseWithSecurity is like Parse but accepts a tlsActive flag. When
// tlsActive is true, Inband-Security-Id=1 (TLS) is accepted because
// the transport is already secured — per RFC 6733 §5.3.1 the peer is
// simply declaring its TLS capability which is already satisfied.
func (cer *CER) ParseWithSecurity(m *diam.Message, localRole Role, tlsActive bool) (failedAVP *diam.AVP, err error) {
	return cer.ParseWithSecurityAndDictionary(m, localRole, tlsActive, m.Dictionary())
}

// ParseWithSecurityAndDictionary validates capabilities against the dictionary
// used to advertise local applications (RFC 6733 §5.3). A nil dictionary uses
// the message dictionary.
func (cer *CER) ParseWithSecurityAndDictionary(m *diam.Message, localRole Role, tlsActive bool, dictionary *dict.Parser) (failedAVP *diam.AVP, err error) {
	return cer.ParseWithSecurityAndApplications(m, localRole, tlsActive, dictionary, nil)
}

// ParseWithSecurityAndApplications intersects the CER with the locally
// advertised application IDs (RFC 6733 §5.3.1).
func (cer *CER) ParseWithSecurityAndApplications(m *diam.Message, localRole Role, tlsActive bool, dictionary *dict.Parser, localIDs []uint32) (failedAVP *diam.AVP, err error) {
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
	failedAVP, err = parsed.ParseWithSecurityAndApplications(m, base.Role(localRole), tlsActive, dictionary, localIDs)
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
