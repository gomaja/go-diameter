package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// capabilities derives advertisement and validation from the same dictionary
// as the connection when Settings.Dict is unset (RFC 6733 §5.3).
func (sm *StateMachine) capabilities(c diam.Conn, m *diam.Message) base.Settings {
	cfg := baseSettings(sm.cfg)
	apps := sm.supportedApps
	if sm.dictionary == nil {
		apps = PrepareSupportedApps(sm.capabilityDictionary(c, m))
	}
	for _, app := range apps {
		cfg.Applications = append(cfg.Applications, base.LocalApplication{
			ID: app.ID, AppType: app.AppType, Vendor: app.Vendor, SupportedVendors: app.SupportedVendors,
		})
	}
	return cfg
}

func (sm *StateMachine) capabilityDictionary(c diam.Conn, m *diam.Message) *dict.Parser {
	if sm.dictionary != nil {
		return sm.dictionary
	}
	if dp := c.Dictionary(); dp != nil {
		return dp
	}
	if m != nil {
		return m.Dictionary()
	}
	return dict.Default
}
