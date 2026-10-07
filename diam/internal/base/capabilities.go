package base

import (
	"fmt"
	"slices"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// mergeApplications preserves the first declaration's author (including an
// absent author) and type. Later declarations only extend its AVP suppliers.
// App declarations arrive in load order; bundled dictionaries use filename order.
func mergeApplications(apps []LocalApplication) []LocalApplication {
	var result []LocalApplication
	indexes := make(map[uint32]int)
	for _, app := range apps {
		if app.ID == 0 {
			continue
		}
		suppliers := slices.Clone(app.SupportedVendors)
		if app.Vendor != 0 {
			suppliers = append(suppliers, app.Vendor)
		}
		if i, ok := indexes[app.ID]; ok {
			result[i].SupportedVendors = append(result[i].SupportedVendors, suppliers...)
			continue
		}
		app.SupportedVendors = suppliers
		if !dict.IsVendorSpecificApplication(app.ID) {
			app.Vendor = 0
		}
		// RFC 6733 §2.4 carries applications in Auth-/Acct-Application-Id.
		// Dictionaries that do not explicitly say accounting default to auth.
		if app.AppType != "acct" {
			app.AppType = "auth"
		}
		indexes[app.ID] = len(result)
		result = append(result, app)
	}
	slices.SortFunc(result, func(a, b LocalApplication) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return result
}

func explicitApplications(cfg Settings) bool {
	return cfg.AuthApplicationID != nil || cfg.AcctApplicationID != nil || cfg.VendorSpecificApplicationID != nil
}

// ValidateCapabilities validates explicit configuration before networking starts.
// RFC 6733 §6.11, Verified Erratum 4808 requires exactly one Vendor-Id and
// exactly one of Auth-Application-Id or Acct-Application-Id in each VSAI.
// The configured values, order and repetitions are otherwise preserved.
func ValidateCapabilities(cfg Settings) error {
	for _, field := range []struct {
		code   uint32
		name   string
		values []*diam.AVP
	}{
		{avp.AuthApplicationID, "Auth-Application-Id", cfg.AuthApplicationID},
		{avp.AcctApplicationID, "Acct-Application-Id", cfg.AcctApplicationID},
		{avp.SupportedVendorID, "Supported-Vendor-Id", cfg.SupportedVendorID},
	} {
		for i, a := range field.values {
			if a == nil {
				return fmt.Errorf("%s[%d]: nil AVP", field.name, i)
			}
			if _, ok := a.Data.(datatype.Unsigned32); !ok || a.Code != field.code || a.VendorID != 0 || a.Flags&avp.Vbit != 0 {
				return fmt.Errorf("%s[%d]: expected an IETF Unsigned32 AVP", field.name, i)
			}
		}
	}
	for i, a := range cfg.VendorSpecificApplicationID {
		if a == nil {
			return fmt.Errorf("Vendor-Specific-Application-Id[%d]: nil AVP", i)
		}
		group, ok := a.Data.(*diam.GroupedAVP)
		if !ok || group == nil || a.Code != avp.VendorSpecificApplicationID || a.VendorID != 0 || a.Flags&avp.Vbit != 0 {
			return fmt.Errorf("Vendor-Specific-Application-Id[%d]: expected an IETF Grouped AVP", i)
		}
		vendors, apps := 0, 0
		for _, child := range group.AVP {
			if child == nil {
				return fmt.Errorf("Vendor-Specific-Application-Id[%d]: nil member", i)
			}
			if child.VendorID != 0 || child.Flags&avp.Vbit != 0 {
				continue
			}
			switch child.Code {
			case avp.VendorID:
				vendors++
			case avp.AuthApplicationID, avp.AcctApplicationID:
				apps++
			default:
				continue
			}
			if _, ok := child.Data.(datatype.Unsigned32); !ok {
				return fmt.Errorf("Vendor-Specific-Application-Id[%d]: member %d must be Unsigned32", i, child.Code)
			}
		}
		if vendors != 1 || apps != 1 {
			return fmt.Errorf("Vendor-Specific-Application-Id[%d]: requires exactly one Vendor-Id and exactly one Auth-Application-Id or Acct-Application-Id (RFC 6733 §6.11, Erratum 4808)", i)
		}
	}
	// RFC 6733 §§2.4 and 5.3: base protocol support is implicit, never advertised.
	for _, app := range advertisedApplications(cfg) {
		if app.ID == 0 {
			return fmt.Errorf("application 0 is implicit and must not be advertised")
		}
	}
	return nil
}

// advertisedApplications supplies metadata for the applications actually sent.
// It never changes explicit AVPs; dictionary metadata only informs inferred
// Supported-Vendor-Id values when that separate list was not configured.
func advertisedApplications(cfg Settings) []LocalApplication {
	available := mergeApplications(cfg.Applications)
	if !explicitApplications(cfg) {
		return available
	}
	metadata := make(map[uint32]LocalApplication, len(available))
	for _, app := range available {
		metadata[app.ID] = app
	}
	var offered []LocalApplication
	offer := func(id uint32, kind string, vendor uint32) {
		app := metadata[id]
		app.ID = id
		app.AppType = kind
		// An explicit VSAI names the author used by this node, including for an
		// application that has no declaration in the dictionary.
		if vendor != 0 {
			app.SupportedVendors = append(slices.Clone(app.SupportedVendors), app.Vendor)
			app.Vendor = vendor
		}
		offered = append(offered, app)
	}
	for _, field := range []struct {
		values []*diam.AVP
		kind   string
	}{{cfg.AuthApplicationID, "auth"}, {cfg.AcctApplicationID, "acct"}} {
		for _, a := range field.values {
			if a != nil {
				if id, ok := a.Data.(datatype.Unsigned32); ok {
					offer(uint32(id), field.kind, 0)
				}
			}
		}
	}
	for _, a := range cfg.VendorSpecificApplicationID {
		if a == nil {
			continue
		}
		group, ok := a.Data.(*diam.GroupedAVP)
		if !ok || group == nil {
			continue
		}
		var id, vendor uint32
		kind := "auth"
		for _, child := range group.AVP {
			if child == nil || child.VendorID != 0 || child.Flags&avp.Vbit != 0 {
				continue
			}
			value, ok := child.Data.(datatype.Unsigned32)
			if !ok {
				continue
			}
			switch child.Code {
			case avp.VendorID:
				vendor = uint32(value)
			case avp.AuthApplicationID:
				id = uint32(value)
			case avp.AcctApplicationID:
				id = uint32(value)
				kind = "acct"
			}
		}
		offer(id, kind, vendor)
	}
	return offered
}

// AdvertisedApplicationIDs returns the effective local application set for
// capabilities negotiation. Explicit lists replace dictionary inference.
func AdvertisedApplicationIDs(cfg Settings) []uint32 {
	ids := make([]uint32, 0)
	for _, app := range advertisedApplications(cfg) {
		ids = append(ids, app.ID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// RFC 6733 §§5.3.1–5.3.2, 6.11 and Verified Erratum 4808: derived VSAIs
// contain one author and one application. Standard IDs, relay and applications
// without an author use plain AVPs, as permitted by §5.3. Explicit AVPs are
// transmitted as configured; validation belongs at configuration time.
func addApplications(m *diam.Message, cfg Settings, apps []LocalApplication) {
	if explicitApplications(cfg) {
		for _, list := range [][]*diam.AVP{cfg.AuthApplicationID, cfg.AcctApplicationID, cfg.VendorSpecificApplicationID} {
			for _, a := range list {
				m.AddAVP(a)
			}
		}
		return
	}
	for _, app := range apps {
		typ := uint32(avp.AuthApplicationID)
		if app.AppType == "acct" {
			typ = avp.AcctApplicationID
		}
		id := diam.NewAVP(typ, avp.Mbit, 0, datatype.Unsigned32(app.ID))
		if dict.IsVendorSpecificApplication(app.ID) && app.Vendor != 0 {
			m.AddAVP(diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
				diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(app.Vendor)), id,
			}}))
		} else {
			m.AddAVP(id)
		}
	}
}

// RFC 6733 §5.3.6 excludes the device vendor but includes application authors.
// In particular a 3GPP device still advertises 10415 for Cx (TS 29.229 V19.1.0
// §5.6) and Sy (TS 29.219 V19.0.0 §5.1.5). Only inferred lists are deduplicated,
// sorted and filtered. A non-nil configured list is transmitted verbatim.
func addSupportedVendors(m *diam.Message, cfg Settings, apps []LocalApplication) {
	if cfg.SupportedVendorID != nil {
		for _, a := range cfg.SupportedVendorID {
			m.AddAVP(a)
		}
		return
	}
	vendors := make(map[uint32]bool)
	authors := make(map[uint32]bool)
	for _, app := range apps {
		if app.Vendor != 0 {
			authors[app.Vendor] = true
			vendors[app.Vendor] = true
		}
		for _, v := range app.SupportedVendors {
			if v != 0 {
				vendors[v] = true
			}
		}
	}
	if !authors[uint32(cfg.VendorID)] {
		delete(vendors, uint32(cfg.VendorID))
	}
	ordered := make([]uint32, 0, len(vendors))
	for v := range vendors {
		ordered = append(ordered, v)
	}
	slices.Sort(ordered)
	for _, v := range ordered {
		m.AddAVP(diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(v)))
	}
}
