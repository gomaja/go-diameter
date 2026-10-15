package base

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// Settings is the wire data needed by base command builders. Callers resolve
// local transport addresses before building capabilities, or supply a resolver.
type Settings struct {
	OriginHost                  datatype.DiameterIdentity
	OriginRealm                 datatype.DiameterIdentity
	VendorID                    datatype.Unsigned32
	ProductName                 datatype.UTF8String
	OriginStateID               datatype.Unsigned32
	FirmwareRevision            datatype.Unsigned32
	HostIPAddresses             []datatype.Address
	ResolveHostIPAddresses      func() ([]datatype.Address, error)
	SupportedVendorID           []*diam.AVP
	AcctApplicationID           []*diam.AVP
	AuthApplicationID           []*diam.AVP
	VendorSpecificApplicationID []*diam.AVP
	InbandSecurityID            uint32
	Applications                []LocalApplication
}

// LocalApplication describes a locally supported application and its vendors.
type LocalApplication struct {
	ID               uint32
	AppType          string
	Vendor           uint32
	SupportedVendors []uint32
}

// BuildCER constructs the RFC 6733 §5.3.1 request.
func BuildCER(dictionary *dict.Parser, cfg Settings) (*diam.Message, error) {
	addresses, err := capabilityAddresses(cfg)
	if err != nil {
		return nil, fmt.Errorf("find local addresses for CER: %w", err)
	}
	apps := advertisedApplications(cfg)
	m := diam.NewRequest(diam.CapabilitiesExchange, 0, dictionary)
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm); err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if _, err := m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address); err != nil {
			return nil, err
		}
	}
	if _, err := m.NewAVP(avp.VendorID, avp.Mbit, 0, cfg.VendorID); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.ProductName, 0, 0, cfg.ProductName); err != nil {
		return nil, err
	}
	if cfg.OriginStateID != 0 {
		if _, err := m.NewAVP(avp.OriginStateID, avp.Mbit, 0, cfg.OriginStateID); err != nil {
			return nil, err
		}
	}
	addSupportedVendors(m, cfg, apps)
	// RFC 6733 §6.10: zero is the omitted default in a CER.
	if cfg.InbandSecurityID != 0 {
		if _, err := m.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unsigned32(cfg.InbandSecurityID)); err != nil {
			return nil, err
		}
	}
	addApplications(m, cfg, apps)
	if cfg.FirmwareRevision != 0 {
		if _, err := m.NewAVP(avp.FirmwareRevision, 0, 0, cfg.FirmwareRevision); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// BuildCEA constructs the RFC 6733 §5.3.2 answer. Non-protocol failures
// retain the mandatory local fields but omit supported apps.
func BuildCEA(request *diam.Message, cfg Settings, resultCode uint32) (*diam.Message, error) {
	// RFC 6733 §§7.1.3 and 7.2: 3xxx results, including Unknown-Peer,
	// require E and the generic answer-message grammar.
	if resultCode >= 3000 && resultCode < 4000 {
		return BuildErrorAnswer(request, cfg, resultCode, nil, true)
	}
	addresses, err := capabilityAddresses(cfg)
	if err != nil {
		return nil, fmt.Errorf("find local addresses for CEA: %w", err)
	}
	a := request.Answer(resultCode)
	var buildErr error
	add := func(code uint32, flags uint8, vendor uint32, data datatype.Type) {
		if buildErr == nil {
			_, buildErr = a.NewAVP(code, flags, vendor, data)
		}
	}
	a.Header.CommandFlags = 0
	a.Header.ApplicationID = 0
	add(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost)
	add(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm)
	for _, address := range addresses {
		add(avp.HostIPAddress, avp.Mbit, 0, address)
	}
	add(avp.VendorID, avp.Mbit, 0, cfg.VendorID)
	add(avp.ProductName, 0, 0, cfg.ProductName)
	// RFC 6733 §8.16: Origin-State-Id reflects the local Origin-Host.
	if cfg.OriginStateID != 0 {
		add(avp.OriginStateID, avp.Mbit, 0, cfg.OriginStateID)
	}
	if resultCode == diam.Success {
		apps := advertisedApplications(cfg)
		addSupportedVendors(a, cfg, apps)
		addApplications(a, cfg, apps)
	}
	if cfg.FirmwareRevision != 0 {
		add(avp.FirmwareRevision, 0, 0, cfg.FirmwareRevision)
	}
	if buildErr != nil {
		return nil, buildErr
	}
	return a, nil
}

// BuildDWR constructs the RFC 6733 §5.5.1 request.
func BuildDWR(dictionary *dict.Parser, cfg Settings, osid uint32) (*diam.Message, error) {
	m := diam.NewRequest(diam.DeviceWatchdog, 0, dictionary)
	if _, err := m.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost); err != nil {
		return nil, err
	}
	if _, err := m.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm); err != nil {
		return nil, err
	}
	if cfg.OriginStateID != 0 {
		if _, err := m.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(osid)); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// BuildDWA constructs the RFC 6733 §5.5.2 success answer.
func BuildDWA(request *diam.Message, cfg Settings) (*diam.Message, error) {
	a := request.Answer(diam.Success)
	a.Header.CommandFlags = 0
	a.Header.ApplicationID = 0
	if _, err := a.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost); err != nil {
		return nil, err
	}
	if _, err := a.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm); err != nil {
		return nil, err
	}
	if cfg.OriginStateID != 0 {
		if _, err := a.NewAVP(avp.OriginStateID, avp.Mbit, 0, cfg.OriginStateID); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// BuildDPR constructs the RFC 6733 §5.4.1 request.
func BuildDPR(dictionary *dict.Parser, cfg Settings, cause uint32) (*diam.Message, error) {
	m := diam.NewRequest(diam.DisconnectPeer, 0, dictionary)
	for _, field := range []struct {
		code uint32
		data datatype.Type
	}{
		{avp.OriginHost, cfg.OriginHost},
		{avp.OriginRealm, cfg.OriginRealm},
		{avp.DisconnectCause, datatype.Enumerated(cause)},
	} {
		if _, err := m.NewAVP(field.code, avp.Mbit, 0, field.data); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// BuildDPA constructs the RFC 6733 §5.4.2 success answer.
func BuildDPA(request *diam.Message, cfg Settings) (*diam.Message, error) {
	return BuildDPAResult(request, cfg, diam.Success)
}

// BuildDPAResult constructs a DPA with the chosen RFC 6733 §5.4 result and
// local identities (§5.4.2; Verified Erratum 4887 for §6.2).
func BuildDPAResult(request *diam.Message, cfg Settings, result uint32) (*diam.Message, error) {
	a := request.Answer(result)
	a.Header.CommandFlags = 0
	a.Header.ApplicationID = 0
	if _, err := a.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost); err != nil {
		return nil, err
	}
	if _, err := a.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm); err != nil {
		return nil, err
	}
	return a, nil
}

// capabilityAddresses enforces RFC 6733 §§5.3.1, 5.3.2 and 5.3.5: a
// capabilities message requires at least one configured or resolved address.
func capabilityAddresses(cfg Settings) ([]datatype.Address, error) {
	addresses := cfg.HostIPAddresses
	if len(addresses) == 0 && cfg.ResolveHostIPAddresses != nil {
		var err error
		addresses, err = cfg.ResolveHostIPAddresses()
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("no usable local Host-IP-Address; configure Settings.HostIPAddresses explicitly for custom transports")
	}
	return addresses, nil
}
