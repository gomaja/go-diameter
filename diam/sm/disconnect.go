package sm

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var (
	ErrDisconnectTimeout = errors.New("diam: DPA timeout")
	ErrDisconnectClosed  = errors.New("diam: disconnect on closed connection")
	ErrDisconnectPending = errors.New("diam: disconnect already pending")
)

type disconnectState struct {
	mu      sync.Mutex
	pending map[diam.Conn]*pendingDisconnect
}

type pendingDisconnect struct {
	request *answerCorrelation
	claimed bool
	result  chan uint32
}

// Disconnect sends a DPR and waits for its matching DPA on conn. It closes
// the transport after the answer, peer closure, or timeout (RFC 6733 §§5.4,
// 5.6). A positive timeout is required. Do not call synchronously from a
// handler on a sequentially dispatched connection: the read loop must remain
// free to receive the DPA.
func (sm *StateMachine) Disconnect(c diam.Conn, cause DisconnectCause, timeout time.Duration) error {
	if c == nil || timeout <= 0 {
		return fmt.Errorf("invalid disconnect connection or timeout")
	}
	if cause > DisconnectDoNotWantToTalkToYou {
		return fmt.Errorf("invalid Disconnect-Cause %d", cause)
	}
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok && lifecycle.RetirementReason() != 0 {
		return ErrDisconnectClosed
	}
	if _, ok := smpeer.FromContext(c.Context()); !ok {
		return fmt.Errorf("disconnect before CER/CEA handshake")
	}
	notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
	if !ok {
		return fmt.Errorf("disconnect requires CloseNotifier")
	}
	if c.Closed() {
		return ErrDisconnectClosed
	}
	closed := notifier.CloseNotify()
	select {
	case <-closed:
		return ErrDisconnectClosed
	default:
	}
	m, err := base.BuildDPR(c.Dictionary(), baseSettings(sm.cfg), uint32(cause))
	if err != nil {
		return err
	}
	p := &pendingDisconnect{request: correlateAnswer(c, m), result: make(chan uint32, 1)}
	sm.disconnects.mu.Lock()
	if sm.disconnects.pending == nil {
		sm.disconnects.pending = make(map[diam.Conn]*pendingDisconnect)
	}
	if sm.disconnects.pending[c] != nil {
		sm.disconnects.mu.Unlock()
		return ErrDisconnectPending
	}
	sm.disconnects.pending[c] = p
	sm.disconnects.mu.Unlock()
	defer func() {
		// RFC 6733 §5.6: retain Closing until the transport is closed, so
		// deferred handshake supervision cannot start during this cleanup.
		c.Close()
		sm.disconnects.mu.Lock()
		delete(sm.disconnects.pending, c)
		sm.disconnects.mu.Unlock()
	}()
	// Arm RFC 6733 §5.6's timeout before joining admitted watchdog work.
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		close(expired)
		c.Close()
		logMessage(c, m, slog.LevelWarn, "sm: disconnect timeout; closing connection", ErrDisconnectTimeout)
		sm.protocolError(c, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
	})
	defer timer.Stop()
	sm.enterClosing(c)
	if !sm.joinClosingWatchdog(c, expired) || c.Closed() {
		select {
		case <-expired:
			return ErrDisconnectTimeout
		default:
			return ErrDisconnectClosed
		}
	}
	if _, err := m.WriteTo(c); err != nil {
		select {
		case <-expired:
			return ErrDisconnectTimeout
		default:
		}
		if c.Closed() || errors.Is(err, diam.ErrConnectionRetired) || errors.Is(err, net.ErrClosed) {
			return ErrDisconnectClosed
		}
		return err
	}
	select {
	case result := <-p.result:
		select {
		case <-expired:
			return ErrDisconnectTimeout
		default:
		}
		if c.Closed() {
			return ErrDisconnectClosed
		}
		if result != diam.Success {
			return fmt.Errorf("DPA Result-Code %d", result)
		}
		return nil
	case <-closed:
		select {
		case <-expired:
			return ErrDisconnectTimeout
		default:
		}
		return ErrDisconnectClosed
	case <-expired:
		return ErrDisconnectTimeout
	}
}

// validateDPA retains the state-machine entry point for existing callers.
func validateDPA(m *diam.Message) (uint32, error) {
	return base.ValidateDPA(m)
}

func handleDPA(sm *StateMachine) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		if c.Closed() {
			return
		}
		sm.disconnects.mu.Lock()
		p := sm.disconnects.pending[c]
		// RFC 6733 §§3, 5.4.2, 6.2.1: only an explicitly pending DPR
		// from this generation can complete. Zero identifiers remain valid.
		if p == nil || p.claimed || !p.request.matches(c, m) {
			mismatched := p != nil && !p.claimed
			sm.disconnects.mu.Unlock()
			if mismatched {
				logMessage(c, m, slog.LevelWarn, "sm: DPA identifiers mismatch; answer discarded", nil)
			}
			sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		sm.disconnects.mu.Unlock()
		result, err := validateDPA(m)
		if err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: invalid DPA", err)
			sm.protocolError(c, m, diam.ProtocolInvalidDPA, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		// RFC 6733 §6.3: bind the structurally valid answer's sender before
		// interpreting Result-Code; another peer cannot end this disconnect.
		if !messageBoundHost(c, m) {
			logMessage(c, m, slog.LevelWarn, "sm: DPA Origin-Host mismatch; answer discarded", nil)
			sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		sm.disconnects.mu.Lock()
		if sm.disconnects.pending[c] != p || p.claimed || !p.request.matches(c, m) {
			sm.disconnects.mu.Unlock()
			sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
			return
		}
		p.claimed = true
		sm.disconnects.mu.Unlock()
		select {
		case p.result <- result:
			if result != diam.Success {
				sm.protocolError(c, m, diam.ProtocolPeerRejected, result, true, diam.ProtocolReplyNone, 0)
			}
		default:
			sm.protocolError(c, m, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		}
	}
}
