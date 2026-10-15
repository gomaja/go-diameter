package sm

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
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
		if state := sm.acceptedCore(c, m, false); state != nil {
			state.apply(protocol.Input{Kind: protocol.Receive, Message: m})
			return
		}
		cause, err := validateDPR(m)
		if err == nil && !messageBoundHost(c, m) {
			err = fmt.Errorf("DPR Origin-Host does not match the admitted peer (RFC 6733 §6.3)")
		}
		if err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: invalid DPR", err)
			sm.protocolError(c, m, diam.ProtocolInvalidDPR, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		state := sm.enterClosing(c)
		state.mu.Lock()
		first := !state.received
		state.received = true
		// A crossed DPR retains the local Disconnect deadline, rather than
		// installing a shorter receiver timeout (RFC 6733 §5.6).
		sm.disconnects.mu.Lock()
		local := sm.disconnects.pending[c] != nil
		sm.disconnects.mu.Unlock()
		if first && !local {
			if _, ok := diam.ConnAs[diam.CloseNotifier](c); ok {
				timeout := sm.cfg.DPRCloseTimeout
				if timeout <= 0 {
					timeout = 5 * time.Second
				}
				state.timer = time.AfterFunc(timeout, func() {
					if c.Closed() {
						return
					}
					c.Close()
					logMessage(c, m, slog.LevelWarn, "sm: Wait-Returns timeout; closing connection", nil)
					sm.protocolError(c, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
				})
			}
		}
		state.mu.Unlock()
		// Publish Closing in arrival order before the reader evaluates a later
		// CER for renewal. The DPA write and observer need not hold admission.
		m.BeginDispatch()()
		if !sm.joinClosingWatchdog(c, nil) {
			return
		}
		// RFC 6733 §§5.4.2, 5.6: send DPA, then wait in Closing for
		// the initiating peer to close the transport.
		result := uint32(diam.Success)
		if requests := pendingRequests(c); requests != nil && requests.HasPending() {
			// RFC 6733 §5.4 recommends an error for messages likely in flight.
			// §7.1.5: 5012 applies when no more specific error describes that
			// condition. It keeps the normal DPA grammar, without the E bit.
			result = diam.UnableToComply
		}
		a, err := base.BuildDPAResult(m, baseSettings(sm.cfg), result)
		if err == nil {
			err = writeRequiredReply(c, a)
		}
		if err != nil {
			logMessage(c, m, slog.LevelError, "sm: DPA failed; closing connection", err)
			sm.requiredReplyFailed(c, m, result)
			return
		}
		if first && sm.cfg.OnDPR != nil {
			sm.cfg.OnDPR(c, cause)
		}
	}
}
