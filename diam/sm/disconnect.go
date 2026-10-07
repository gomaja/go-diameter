package sm

import (
	"errors"
	"fmt"
	"log/slog"
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
	hopID  uint32
	result chan uint32
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
	if _, ok := smpeer.FromContext(c.Context()); !ok {
		return fmt.Errorf("disconnect before CER/CEA handshake")
	}
	notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
	if !ok {
		return fmt.Errorf("disconnect requires CloseNotifier")
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
	p := &pendingDisconnect{hopID: m.Header.HopByHopID, result: make(chan uint32, 1)}
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
		sm.disconnects.mu.Lock()
		delete(sm.disconnects.pending, c)
		sm.disconnects.mu.Unlock()
		c.Close()
	}()
	expired := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		logMessage(c, m, slog.LevelWarn, "sm: disconnect timeout; closing connection", ErrDisconnectTimeout)
		close(expired)
		c.Close()
	})
	defer timer.Stop()
	if _, err := m.WriteTo(c); err != nil {
		select {
		case <-expired:
			return ErrDisconnectTimeout
		default:
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
		sm.disconnects.mu.Lock()
		p := sm.disconnects.pending[c]
		if p == nil || p.hopID != m.Header.HopByHopID {
			sm.disconnects.mu.Unlock()
			return
		}
		sm.disconnects.mu.Unlock()
		result, err := validateDPA(m)
		if err != nil {
			logMessage(c, m, slog.LevelWarn, "sm: invalid DPA", err)
			return
		}
		select {
		case p.result <- result:
		default:
		}
	}
}
