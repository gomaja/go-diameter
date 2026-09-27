package sm

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
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
	notifier, ok := c.(diam.CloseNotifier)
	if !ok {
		return fmt.Errorf("disconnect requires CloseNotifier")
	}
	closed := notifier.CloseNotify()
	select {
	case <-closed:
		return ErrDisconnectClosed
	default:
	}
	m := diam.NewRequest(diam.DisconnectPeer, 0, c.Dictionary())
	for _, field := range []struct {
		code uint32
		data datatype.Type
	}{
		{avp.OriginHost, sm.cfg.OriginHost},
		{avp.OriginRealm, sm.cfg.OriginRealm},
		{avp.DisconnectCause, datatype.Enumerated(cause)},
	} {
		if _, err := m.NewAVP(field.code, avp.Mbit, 0, field.data); err != nil {
			return err
		}
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

// validateDPA enforces the required single AVPs of RFC 6733 §5.4.2.
func validateDPA(m *diam.Message) (uint32, error) {
	if m.Header.ApplicationID != 0 || m.Header.CommandCode != diam.DisconnectPeer || m.Header.CommandFlags&diam.RequestFlag != 0 {
		return 0, fmt.Errorf("invalid DPA header")
	}
	var host, realm, result int
	var code uint32
	for _, a := range m.AVP {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case avp.OriginHost:
			host++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPA Origin-Host")
			}
		case avp.OriginRealm:
			realm++
			if v, ok := a.Data.(datatype.DiameterIdentity); !ok || len(v) == 0 {
				return 0, fmt.Errorf("invalid DPA Origin-Realm")
			}
		case avp.ResultCode:
			result++
			v, ok := a.Data.(datatype.Unsigned32)
			if !ok {
				return 0, fmt.Errorf("invalid DPA Result-Code")
			}
			code = uint32(v)
		}
	}
	if host != 1 || realm != 1 || result != 1 {
		return 0, fmt.Errorf("DPA requires one Result-Code, Origin-Host and Origin-Realm")
	}
	return code, nil
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
			sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			return
		}
		select {
		case p.result <- result:
		default:
		}
	}
}
