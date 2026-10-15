package protocol

import (
	"slices"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func copySettings(s base.Settings) base.Settings {
	s.HostIPAddresses = base.CloneAddresses(s.HostIPAddresses)
	s.SupportedVendorID = base.CloneAVPs(s.SupportedVendorID)
	s.AuthApplicationID = base.CloneAVPs(s.AuthApplicationID)
	s.AcctApplicationID = base.CloneAVPs(s.AcctApplicationID)
	s.VendorSpecificApplicationID = base.CloneAVPs(s.VendorSpecificApplicationID)
	s.Applications = slices.Clone(s.Applications)
	for i := range s.Applications {
		s.Applications[i].SupportedVendors = slices.Clone(s.Applications[i].SupportedVendors)
	}
	return s
}
func copyCER(p *base.CER) *base.CER {
	if p == nil {
		return nil
	}
	return &base.CER{OriginHost: p.OriginHost, OriginRealm: p.OriginRealm,
		HostIPAddresses: base.CloneAddresses(p.HostIPAddresses), OriginStateID: base.CloneAVP(p.OriginStateID), InbandSecurityID: base.CloneAVP(p.InbandSecurityID),
		AcctApplicationID: base.CloneAVPs(p.AcctApplicationID), AuthApplicationID: base.CloneAVPs(p.AuthApplicationID), VendorSpecificApplicationID: base.CloneAVPs(p.VendorSpecificApplicationID)}
}
func copyCEA(p *base.CEA) *base.CEA {
	if p == nil {
		return nil
	}
	return &base.CEA{OriginHost: p.OriginHost, OriginRealm: p.OriginRealm, ResultCode: p.ResultCode, OriginStateID: p.OriginStateID, VendorID: p.VendorID, ProductName: p.ProductName, ErrorMessage: p.ErrorMessage,
		HostIPAddresses: base.CloneAddresses(p.HostIPAddresses), SupportedVendorID: base.CloneAVPs(p.SupportedVendorID), FailedAVP: base.CloneAVPs(p.FailedAVP),
		AcctApplicationID: base.CloneAVPs(p.AcctApplicationID), AuthApplicationID: base.CloneAVPs(p.AuthApplicationID), VendorSpecificApplicationID: base.CloneAVPs(p.VendorSpecificApplicationID)}
}
func copyCapabilities(s Capabilities) Capabilities {
	s.Local = copySettings(s.Local)
	s.CER = copyCER(s.CER)
	s.CEA = copyCEA(s.CEA)
	s.LocalApplications = slices.Clone(s.LocalApplications)
	s.RemoteApplications = slices.Clone(s.RemoteApplications)
	s.CommonApplications = slices.Clone(s.CommonApplications)
	s.ParsedApplications = slices.Clone(s.ParsedApplications)
	return s
}
func (s Snapshot) Capabilities() Capabilities { return copyCapabilities(s.capabilities) }

// copyMessage preserves dictionary/decode/stream metadata while detaching the
// fields hooks can mutate. Required replies themselves are not reconstructed:
// base.BuildErrorAnswer owns opaque Proxy-Info echo evidence (RFC 6733 §6.2).
func copyMessage(m *diam.Message) *diam.Message {
	if m == nil {
		return nil
	}
	out := *m
	if m.Header != nil {
		h := *m.Header
		out.Header = &h
	}
	out.AVP = base.CloneAVPs(m.AVP)
	return &out
}
func (c *Core) negotiate(host, realm string, apps []uint32) {
	c.caps.Host, c.caps.Realm = host, realm
	c.caps.RemoteApplications = slices.Clone(apps)
	c.caps.CommonApplications = nil
	for _, id := range c.caps.LocalApplications {
		if slices.Contains(apps, id) || slices.Contains(apps, uint32(0xffffffff)) {
			c.caps.CommonApplications = append(c.caps.CommonApplications, id)
		}
	}
	if slices.Contains(c.caps.LocalApplications, uint32(0xffffffff)) {
		c.caps.CommonApplications = slices.Clone(apps)
	}
}

// Identity binding is the #108 policy around RFC 6733 §§4.3,6.3. Fold ASCII
// octets only; Unicode case folding would join distinct Diameter identities.
func equalIdentity(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
