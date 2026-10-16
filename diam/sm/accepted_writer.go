package sm

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func (s *acceptedHandshake) send(e protocol.Effect, source protocol.Input, observer *acceptedObservation) {
	m := e.Message
	cer := s.client != nil && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
	if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag == 0 {
		s.joinWatchdog()
	}
	// Core retirement invalidates selected effects even on custom transports
	// without a native generation write gate (RFC 6733 §§5.5.4,5.6).
	if s.conn.Closed() && !cer || s.phase() >= protocol.Closed {
		observer.finish()
		s.apply(protocol.Input{Kind: protocol.WriteResult, Token: e.Token, Stage: protocol.SkippedStage, Err: diam.ErrConnectionRetired, ReplyCode: protocolAnswerCode(m)})
		return
	}
	probe := m.Header.CommandCode == diam.DeviceWatchdog && m.Header.CommandFlags&diam.RequestFlag != 0
	tracked := probe || s.client != nil && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
	var w *acceptedWatchdog
	if probe {
		observer.wait()
		defer observer.finish()
		w = s.watchdogState()
		if w != nil {
			w.mu.Lock()
			defer w.mu.Unlock()
		}
	}
	if e.Notification.Protocol != "" && e.Notification.Diagnostic != "external-reject-cer" {
		s.record(source, e.Notification)
	}
	if m.Header.CommandFlags&diam.RequestFlag == 0 {
		if m.Header.CommandCode == diam.CapabilitiesExchange && s.sm.cfg.OnCEA != nil {
			s.sm.cfg.OnCEA(s.conn, m)
		}
		if e.AnswerHook && m.Header.CommandCode == diam.DeviceWatchdog && s.sm.cfg.OnDWA != nil {
			s.sm.cfg.OnDWA(s.conn, m)
		}
	}
	var ticket *diam.RequestWrite
	settled := false
	if tracked {
		if requests := pendingRequests(s.conn); requests != nil {
			ticket = requests.PrepareWrite(m.Header)
		}
		s.mu.Lock()
		active := false
		for _, control := range s.core.Snapshot().Controls() {
			if control.Command == m.Header.CommandCode && control.Logical && control.Reservation.Hop == m.Header.HopByHopID && control.Reservation.End == m.Header.EndToEndID {
				active = true
				break
			}
		}
		if !active {
			ticket.Cancel()
			settled = true
		}
		if s.writeHeaders == nil {
			s.writeHeaders = make(map[uint64]diam.Header)
		}
		s.writes[e.Token] = ticket
		s.writeHeaders[e.Token] = *m.Header
		s.mu.Unlock()
	}
	// Check after hooks and writer selection. Native write gates fence a racing
	// Closing/retirement as well (RFC 6733 §5.6; #125).
	skipped := settled || s.conn.Closed() && !cer || probe && (w == nil || w.stopped.Load() || s.phase() != protocol.Open)
	var n int64
	var err error
	if skipped {
		err = diam.ErrConnectionClosing
	} else if probe {
		var count int
		count, err = m.WriteToStream(s.conn, s.policy.stream)
		n = int64(count)
	} else {
		n, err = m.WriteTo(s.conn)
	}
	if err == nil && n != int64(m.Len()) {
		err = io.ErrShortWrite
	}
	if s.client != nil && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0 {
		// Dial's first write is synchronous. A fast successful CEA cannot
		// hide that write's real return value (RFC 6733 §§3,5.3).
		s.mu.Lock()
		if !s.initialCERDone {
			s.initialCERDone, s.initialCERErr = true, err
		}
		s.mu.Unlock()
	}
	if tracked {
		s.mu.Lock()
		delete(s.writes, e.Token)
		delete(s.writeHeaders, e.Token)
		s.mu.Unlock()
		ticket.Release()
	}
	// Only a zero-byte gate rejection proves that publication was skipped.
	// Stopping observations cannot erase an attempted write's failure, and a
	// partial frame still requires termination (RFC 6733 §§3,5.4,5.6).
	if tracked && n == 0 && (errors.Is(err, diam.ErrConnectionClosing) || errors.Is(err, diam.ErrRequestCompleted) || errors.Is(err, diam.ErrConnectionRetired)) {
		skipped = true
	}
	if err != nil && !probe && m.Header.CommandFlags&diam.RequestFlag != 0 && m.Header.CommandCode == diam.DisconnectPeer && !s.conn.Closed() && !errors.Is(err, net.ErrClosed) && !errors.Is(err, diam.ErrConnectionRetired) {
		s.mu.Lock()
		waiter := s.waiter
		s.mu.Unlock()
		if waiter != nil {
			// A buffered result already completes this one-shot Disconnect waiter.
			select {
			case waiter <- err:
			default:
			}
		}
	}
	if err != nil && !skipped {
		if probe && w != nil {
			w.closing.Add(1)
			defer w.closing.Done()
		}
		text := "sm: error answer failed"
		switch m.Header.CommandCode {
		case diam.CapabilitiesExchange:
			if e.Notification.Protocol == "" || e.Notification.Protocol == diam.ProtocolCERRejected {
				text = "sm: CEA failed; closing connection"
			}
		case diam.DeviceWatchdog:
			if probe {
				text = "sm: watchdog request failed; closing connection"
			} else if e.Notification.Protocol == "" {
				text = "sm: DWA failed"
			}
		case diam.DisconnectPeer:
			if e.Notification.Protocol == "" {
				text = "sm: DPA failed; closing connection"
			}
		}
		if probe && w != nil {
			w.emit(WatchdogWriteFailed)
		}
		if e.Required || probe && (s.client == nil || w != nil && !w.stopped.Load() && !s.conn.Closed()) {
			message := source.Message
			if probe && s.client != nil {
				message = m
			}
			logMessage(s.conn, message, slog.LevelError, text, err)
		}
	}
	in := protocol.Input{Kind: protocol.WriteResult, Token: e.Token, Stage: protocol.WrittenStage, At: time.Now(), Message: source.Message, Bytes: n, ExpectedBytes: int64(m.Len()), ReplyCode: protocolAnswerCode(m), Err: err, Error: source.Error}
	if skipped {
		in.Stage = protocol.SkippedStage
	}
	batch := s.prepare(in)
	if probe && !skipped && err == nil && w != nil {
		w.emit(WatchdogRequestSent)
	}
	observer.finish()
	// Write-result effects must not re-enter the watchdog observer lock.
	if probe && w != nil {
		w.mu.Unlock()
		s.run(batch)
		w.mu.Lock()
	} else {
		s.run(batch)
	}
}
