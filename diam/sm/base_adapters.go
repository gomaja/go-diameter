package sm

import "github.com/gomaja/go-diameter/diam/internal/base"

func baseSettings(cfg *Settings) base.Settings {
	return base.Settings{
		OriginHost:                  cfg.OriginHost,
		OriginRealm:                 cfg.OriginRealm,
		VendorID:                    cfg.VendorID,
		ProductName:                 cfg.ProductName,
		OriginStateID:               cfg.OriginStateID,
		FirmwareRevision:            cfg.FirmwareRevision,
		HostIPAddresses:             cfg.HostIPAddresses,
		SupportedVendorID:           cfg.SupportedVendorID,
		AuthApplicationID:           cfg.AuthApplicationID,
		AcctApplicationID:           cfg.AcctApplicationID,
		VendorSpecificApplicationID: cfg.VendorSpecificApplicationID,
	}
}
