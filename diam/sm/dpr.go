package sm

import (
	"log/slog"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// DisconnectCause is the reason carried in a DPR (RFC 6733 §5.4.3).
type DisconnectCause uint32

const (
	DisconnectRebooting            DisconnectCause = 0
	DisconnectBusy                 DisconnectCause = 1
	DisconnectDoNotWantToTalkToYou DisconnectCause = 2
)

// validateDPR retains the state-machine result type for existing callers.
func validateDPR(m *diam.Message) (DisconnectCause, error) {
	cause, err := base.ValidateDPR(m)
	return DisconnectCause(cause), err
}

func handleDPR(sm *StateMachine) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		cause, err := validateDPR(m)
		if err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: invalid DPR", err)
			return
		}
		sm.stopWatchdog(c) // RFC 6733 §5.6: R-Rcv-DPR enters Closing.
		// RFC 6733 §§5.4.2, 5.6: send DPA, then wait in Closing for
		// the initiating peer to close the transport.
		a, err := base.BuildDPA(m, baseSettings(sm.cfg))
		if err == nil {
			_, err = a.WriteTo(c)
		}
		if err != nil {
			logMessage(c, m, slog.LevelError, "sm: DPA failed; closing connection", err)
			c.Close()
			return
		}
		if notifier, ok := diam.ConnAs[diam.CloseNotifier](c); ok {
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
					logMessage(c, m, slog.LevelWarn, "sm: Wait-Returns timeout; closing connection", nil)
					c.Close()
				}
			}()
		}
		if sm.cfg.OnDPR != nil {
			sm.cfg.OnDPR(c, cause)
		}
	}
}
