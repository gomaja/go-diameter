// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package smparser

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// CEA is a Capabilities-Exchange-Answer message.
// See RFC 6733 section 5.3.2 for details.
type CEA struct {
	HostIPAddresses             []datatype.Address        `avp:"Host-IP-Address"`
	ResultCode                  uint32                    `avp:"Result-Code"`
	OriginHost                  datatype.DiameterIdentity `avp:"Origin-Host"`
	OriginRealm                 datatype.DiameterIdentity `avp:"Origin-Realm"`
	OriginStateID               uint32                    `avp:"Origin-State-Id"`
	VendorID                    uint32                    `avp:"Vendor-Id"`           // Peer's Vendor-Id (RFC 6733 §5.3.2, mandatory).
	ProductName                 string                    `avp:"Product-Name"`        // Peer's Product-Name (RFC 6733 §5.3.2, mandatory).
	SupportedVendorID           []*diam.AVP               `avp:"Supported-Vendor-Id"` // Vendor-Ids the peer supports (RFC 6733 §5.3.2).
	AcctApplicationID           []*diam.AVP               `avp:"Acct-Application-Id"`
	AuthApplicationID           []*diam.AVP               `avp:"Auth-Application-Id"`
	VendorSpecificApplicationID []*diam.AVP               `avp:"Vendor-Specific-Application-Id"`
	FailedAVP                   []*diam.AVP               `avp:"Failed-AVP"`
	ErrorMessage                string                    `avp:"Error-Message"`
	appID                       []uint32                  // List of supported application IDs.
}

// ErrFailedResultCode is returned by Dial or DialTLS when the handshake
// answer (CEA) contains a Result-Code AVP that is not success (2001).
type ErrFailedResultCode struct {
	*CEA
}

// Error implements the error interface.
func (e ErrFailedResultCode) Error() string {
	return fmt.Sprintf("failed Result-Code AVP: %d", e.ResultCode)
}

// Parse parses and validates the given message.
func (cea *CEA) Parse(m *diam.Message, localRole Role) error {
	return cea.ParseWithApplicationIDs(m, localRole, nil)
}

// ParseWithApplicationIDs intersects the CEA with the applications offered
// in this connection's CER (RFC 6733 §5.3.2).
func (cea *CEA) ParseWithApplicationIDs(m *diam.Message, localRole Role, localIDs []uint32) error {
	parsed := &base.CEA{
		HostIPAddresses:             cea.HostIPAddresses,
		ResultCode:                  cea.ResultCode,
		OriginHost:                  cea.OriginHost,
		OriginRealm:                 cea.OriginRealm,
		OriginStateID:               cea.OriginStateID,
		VendorID:                    cea.VendorID,
		ProductName:                 cea.ProductName,
		SupportedVendorID:           cea.SupportedVendorID,
		AcctApplicationID:           cea.AcctApplicationID,
		AuthApplicationID:           cea.AuthApplicationID,
		VendorSpecificApplicationID: cea.VendorSpecificApplicationID,
		FailedAVP:                   cea.FailedAVP,
		ErrorMessage:                cea.ErrorMessage,
	}
	err := parsed.ParseWithApplicationIDs(m, base.Role(localRole), localIDs)
	cea.ResultCode = parsed.ResultCode
	cea.HostIPAddresses = parsed.HostIPAddresses
	cea.OriginHost = parsed.OriginHost
	cea.OriginRealm = parsed.OriginRealm
	cea.OriginStateID = parsed.OriginStateID
	cea.VendorID = parsed.VendorID
	cea.ProductName = parsed.ProductName
	cea.SupportedVendorID = parsed.SupportedVendorID
	cea.AcctApplicationID = parsed.AcctApplicationID
	cea.AuthApplicationID = parsed.AuthApplicationID
	cea.VendorSpecificApplicationID = parsed.VendorSpecificApplicationID
	cea.FailedAVP = parsed.FailedAVP
	cea.ErrorMessage = parsed.ErrorMessage
	if err == nil {
		cea.appID = parsed.Applications()
	}
	if _, ok := err.(*base.ErrFailedResultCode); ok {
		return &ErrFailedResultCode{CEA: cea}
	}
	return adaptError(err)
}

// Applications return a list of supported Application IDs.
func (cea *CEA) Applications() []uint32 {
	return cea.appID
}

// Clone returns an independent copy of the parsed CEA, including AVPs and
// the application list used by peer metadata.
func (cea *CEA) Clone() *CEA {
	if cea == nil {
		return nil
	}
	copy := *cea
	copy.HostIPAddresses = base.CloneAddresses(cea.HostIPAddresses)
	copy.appID = append([]uint32(nil), cea.appID...)
	copy.SupportedVendorID = base.CloneAVPs(cea.SupportedVendorID)
	copy.AcctApplicationID = base.CloneAVPs(cea.AcctApplicationID)
	copy.AuthApplicationID = base.CloneAVPs(cea.AuthApplicationID)
	copy.VendorSpecificApplicationID = base.CloneAVPs(cea.VendorSpecificApplicationID)
	copy.FailedAVP = base.CloneAVPs(cea.FailedAVP)
	return &copy
}
