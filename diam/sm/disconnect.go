package sm

import (
	"errors"
	"fmt"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var (
	ErrDisconnectTimeout = errors.New("diam: DPA timeout")
	ErrDisconnectClosed  = errors.New("diam: disconnect on closed connection")
	ErrDisconnectPending = errors.New("diam: disconnect already pending")
)

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
	if state := sm.acceptedCoreWithAdmission(c, nil, true, true); state != nil {
		return sm.acceptedDisconnect(state, cause, timeout)
	}
	return ErrDisconnectClosed
}

func (s *acceptedHandshake) completeDisconnect(n protocol.Notification) {
	var err error
	switch n.Outcome {
	case protocol.TimedOut:
		err = ErrDisconnectTimeout
	case protocol.AlreadyPending:
		err = ErrDisconnectPending
	case protocol.Completed:
		if n.ResultCode != diam.Success {
			err = fmt.Errorf("DPA Result-Code %d", n.ResultCode)
		}
	default:
		err = ErrDisconnectClosed
	}
	s.mu.Lock()
	waiter := s.waiter
	s.mu.Unlock()
	if waiter != nil {
		// A buffered writer error already completes this one-shot waiter.
		select {
		case waiter <- err:
		default:
		}
	}
}

func (sm *StateMachine) acceptedDisconnect(s *acceptedHandshake, cause DisconnectCause, timeout time.Duration) error {
	if s.conn.Closed() {
		return ErrDisconnectClosed
	}
	s.mu.Lock()
	if s.waiter != nil {
		s.mu.Unlock()
		return ErrDisconnectPending
	}
	waiter := make(chan error, 1)
	s.waiter = waiter
	s.waiterToken++
	token := s.waiterToken
	s.mu.Unlock()
	defer func() { s.conn.Close(); s.mu.Lock(); s.waiter = nil; s.mu.Unlock() }()
	batch := s.prepare(protocol.Input{Kind: protocol.Disconnect, Cause: uint32(cause), Timeout: timeout, Token: token})
	// The deadline/retirement can complete the waiter while an observer or custom
	// writer is blocked. The caller never waits for the writer to exit.
	go s.run(batch)
	select {
	case err := <-waiter:
		return err
	case <-mustCloseNotify(s.conn):
		select {
		case err := <-waiter:
			return err
		default:
		}
		s.apply(protocol.Input{Kind: protocol.TransportLost})
		select {
		case err := <-waiter:
			return err
		default:
			return ErrDisconnectClosed
		}
	}
}
func mustCloseNotify(c diam.Conn) <-chan struct{} {
	n, _ := diam.ConnAs[diam.CloseNotifier](c)
	return n.CloseNotify()
}
