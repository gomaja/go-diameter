package sm

import (
	"fmt"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// DisconnectCause is the reason carried in a DPR (RFC 6733 §5.4.3).
type DisconnectCause uint32

const (
	DisconnectRebooting            DisconnectCause = 0
	DisconnectBusy                 DisconnectCause = 1
	DisconnectDoNotWantToTalkToYou DisconnectCause = 2
)

// validateDPR enforces the required single AVPs of RFC 6733 §5.4.1.
func validateDPR(m *diam.Message) (DisconnectCause, error) {
	if m.Header.ApplicationID != 0 || m.Header.CommandCode != diam.DisconnectPeer || m.Header.CommandFlags&diam.RequestFlag == 0 {
		return 0, fmt.Errorf("invalid DPR header")
	}
	var host, realm, cause int
	var value DisconnectCause
	for _, a := range m.AVP {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case avp.OriginHost:
			host++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPR Origin-Host")
			}
		case avp.OriginRealm:
			realm++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPR Origin-Realm")
			}
		case avp.DisconnectCause:
			cause++
			v, ok := a.Data.(datatype.Enumerated)
			if !ok || v < 0 || v > 2 {
				return 0, fmt.Errorf("invalid DPR Disconnect-Cause")
			}
			value = DisconnectCause(v)
		}
	}
	if host != 1 || realm != 1 || cause != 1 {
		return 0, fmt.Errorf("DPR requires one Origin-Host, Origin-Realm and Disconnect-Cause")
	}
	return value, nil
}

func handleDPR(sm *StateMachine) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		cause, err := validateDPR(m)
		if err != nil {
			sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			return
		}
		// RFC 6733 §§5.4.2, 5.6: send DPA, then wait in Closing for
		// the initiating peer to close the transport.
		a := m.Answer(diam.Success)
		a.Header.CommandFlags = 0 // RFC 6733 §5.4.2: DPA has no P, E or T bit.
		a.Header.ApplicationID = 0
		if _, err = a.NewAVP(avp.OriginHost, avp.Mbit, 0, sm.cfg.OriginHost); err == nil {
			_, err = a.NewAVP(avp.OriginRealm, avp.Mbit, 0, sm.cfg.OriginRealm)
		}
		if err == nil {
			_, err = a.WriteTo(c)
		}
		if err != nil {
			sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			c.Close()
			return
		}
		if notifier, ok := c.(diam.CloseNotifier); ok {
			timeout := sm.cfg.DPRCloseTimeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			go func() {
				timer := time.NewTimer(timeout)
				defer timer.Stop()
				select {
				case <-notifier.CloseNotify():
				case <-timer.C:
					c.Close()
				}
			}()
		}
		if sm.cfg.OnDPR != nil {
			sm.cfg.OnDPR(c, cause)
		}
	}
}
