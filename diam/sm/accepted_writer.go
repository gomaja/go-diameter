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
	if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag == 0 {
		s.joinWatchdog()
	}
	// Core retirement invalidates selected effects even on custom transports
	// without a native generation write gate (RFC 6733 §§5.5.4,5.6).
	if s.conn.Closed() || s.snapshot().Phase() >= protocol.Closed {
		observer.finish()
		s.apply(protocol.Input{Kind: protocol.WriteResult, Token: e.Token, Stage: protocol.SkippedStage, Err: diam.ErrConnectionRetired, ReplyCode: protocolAnswerCode(m)})
		return
	}
	probe := m.Header.CommandCode == diam.DeviceWatchdog && m.Header.CommandFlags&diam.RequestFlag != 0
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
	if e.Notification.Protocol != "" {
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
	if probe {
		if requests := pendingRequests(s.conn); requests != nil {
			ticket = requests.PrepareWrite(m.Header)
		}
		s.mu.Lock()
		s.writes[e.Token] = ticket
		s.mu.Unlock()
	}
	// Check after hooks and writer selection. Native write gates fence a racing
	// Closing/retirement as well (RFC 6733 §5.6; #125).
	skipped := s.conn.Closed() || probe && (w == nil || w.stopped.Load() || s.snapshot().Phase() != protocol.Open)
	var n int64
	var err error
	if skipped {
		err = diam.ErrConnectionClosing
	} else if probe {
		var count int
		count, err = m.WriteToStream(s.conn, s.sm.watchdog.stream)
		n = int64(count)
	} else {
		n, err = m.WriteTo(s.conn)
	}
	if err == nil && n != int64(m.Len()) {
		err = io.ErrShortWrite
	}
	if probe {
		s.mu.Lock()
		delete(s.writes, e.Token)
		s.mu.Unlock()
		ticket.Release()
	}
	// Only a zero-byte gate rejection proves that publication was skipped.
	// Stopping observations cannot erase an attempted write's failure, and a
	// partial frame still requires termination (RFC 6733 §§3,5.4,5.6).
	if probe && n == 0 && (errors.Is(err, diam.ErrConnectionClosing) || errors.Is(err, diam.ErrRequestCompleted) || errors.Is(err, diam.ErrConnectionRetired)) {
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
		if e.Required || probe {
			logMessage(s.conn, source.Message, slog.LevelError, text, err)
		}
	}
	in := protocol.Input{Kind: protocol.WriteResult, Token: e.Token, Stage: protocol.WrittenStage, At: time.Now(), Message: source.Message, Bytes: n, ExpectedBytes: int64(m.Len()), ReplyCode: protocolAnswerCode(m), Err: err}
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
