package protocol

import (
	"fmt"
	"slices"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// PeerClaims describes admission supplied by a frontend's connection context.
// LocalApplications is the exact saved local offer, including an absent offer.
type PeerClaims struct {
	Host, Realm                           string
	LocalApplications, RemoteApplications []uint32
	CER                                   bool // consumes repeated CER silently when no CEA metadata was supplied
}

// NewAdmitted adopts an existing frontend admission without repeating the CER
// exchange, publishing metadata, invoking callbacks or starting supervision.
// The ordinary base-message rules still apply (RFC 6733 §§5.3–5.6).
func NewAdmitted(cfg Config, peer PeerClaims) (*Core, error) {
	cfg.Role = Responder
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	c.passiveResponder, c.passiveWatchdog = true, cfg.Watchdog
	c.started = true
	c.RefreshAdmission(&peer)
	return c, nil
}

// PassiveResponder reports whether admission still belongs to the frontend's
// externally supplied metadata. Call under the core's serialization domain.
func (c *Core) PassiveResponder() bool { return c.passiveResponder }

// ExternalAdmission reports whether live frontend claims still admit this peer.
// Call under the core serialization domain.
func (c *Core) ExternalAdmission() bool { return c.passiveResponder && c.passivePresent }

// RefreshAdmission updates external claims in the same serialization domain as
// receiving messages. Revocation restores CER gating; live claims still change
// during Closing without reopening it. Closed and retired generations remain
// inert. A genuine CER permanently resumes ordinary responder ownership.
func (c *Core) RefreshAdmission(peer *PeerClaims) {
	if !c.passiveResponder || c.phase >= Closed {
		return
	}
	if peer == nil {
		c.passivePresent = false
		if c.phase == Open {
			c.phase, c.ready = PreCER, false
		}
		c.caps.Host, c.caps.Realm = "", ""
		c.caps.RemoteApplications, c.caps.CommonApplications = nil, nil
		c.caps.LocalApplications = nil
		if c.phase == PreCER {
			c.caps.LocalApplications = base.AdvertisedApplicationIDs(c.cfg.Local)
			c.cfg.Watchdog = c.passiveWatchdog
		}
		return
	}
	c.passivePresent = true
	if c.phase != Closing {
		c.phase, c.ready = Open, true
		c.cfg.Watchdog = false
	}
	c.passiveCER = peer.CER
	c.caps.LocalApplications = slices.Clone(peer.LocalApplications)
	c.negotiate(peer.Host, peer.Realm, peer.RemoteApplications)
}

// ValidateMessageError checks API error descriptions before committing receive
// effects. Externally admitted peers retain their answer and repeated-CER
// exceptions; request validation may supersede an incomplete decoder diagnosis.
func (c *Core) ValidateMessageError(in Input) error {
	m, me := in.Message, in.Error
	if c.passiveResponder && in.TransportClosed {
		return nil
	}
	external := c.ExternalAdmission()
	if external && c.phase == Closing && m != nil {
		return nil
	}
	if me == nil {
		if external && m != nil && (m.Header == nil || m.Header.CommandFlags&diam.RequestFlag == 0 || m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.ApplicationID == 0 || base.ValidateHeader(m) != nil) {
			return nil
		}
		return fmt.Errorf("cannot answer a nil Diameter message error")
	}
	if c.phase == WaitCEA || me.ResultCode != diam.InvalidAVPLength || me.FailedAVP != nil || m == nil || m.Header == nil || m.Header.CommandFlags&diam.RequestFlag == 0 {
		return nil
	}
	if external {
		if m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.ApplicationID == 0 && !me.Fatal || base.ValidateHeader(m) != nil && !base.FatalHeaderError(me) {
			return nil
		}
		if !me.Fatal && !base.IsCommand(m) {
			if rejection := base.ValidateRequest(m, c.caps.LocalApplications, c.cfg.ValidateRequests, c.cfg.RejectUnknownMandatoryAVPs, me); rejection != nil && rejection.Code != diam.InvalidAVPLength {
				return nil
			}
		}
	}
	return fmt.Errorf("diameter result code %d requires Failed-AVP", me.ResultCode)
}
