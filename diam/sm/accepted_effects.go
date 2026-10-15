package sm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
	"github.com/gomaja/go-diameter/diam/sm/internal/parserbridge"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// fromValidatedCER is smparser's private conversion; smparser installs it
// before this package initializes.
var fromValidatedCER = parserbridge.FromValidatedCER.(func(*base.CER, []uint32) *smparser.CER)

func (s *acceptedHandshake) run(batch acceptedBatch) {
	defer func() {
		for _, o := range batch.observers {
			o.finish()
		}
	}()
	if batch.releaseDispatch {
		batch.input.Message.BeginDispatch()()
	}
	if batch.input.Kind == protocol.TimerExpired && batch.input.Timer == protocol.WatchdogTimer {
		if w := s.watchdogState(); w != nil {
			terminal := false
			for _, e := range batch.effects {
				if e.Kind == protocol.Close {
					terminal = true
				}
			}
			if terminal {
				w.mu.Lock()
				if w.stopped.Load() || s.conn.Closed() {
					w.mu.Unlock()
					return
				}
				w.closing.Add(1)
				w.mu.Unlock()
				defer w.closing.Done()
			}
		}
	}
	// Logs complete before the corresponding Close and observer publication.
	for i, e := range batch.effects {
		var observer *acceptedObservation
		if i < len(batch.observers) {
			observer = batch.observers[i]
		}
		if e.Kind == protocol.Notify {
			switch e.Notification.Protocol {
			case diam.ProtocolInvalidDWA, diam.ProtocolRejectedDWA:
				observer.call(func() { s.emit(WatchdogInvalidAnswer) })
			case diam.ProtocolWatchdogTimeout:
				observer.call(func() { s.emit(WatchdogTimedOut) })
			}
		}
		if e.Kind == protocol.Notify && e.Notification.Protocol != "" && e.Notification.Protocol != diam.ProtocolDisconnectTimeout {
			if batch.input.Kind != protocol.WriteResult {
				s.record(batch.input, e.Notification)
			} else if e.Notification.Protocol == diam.ProtocolUnsupportedCommand || e.Notification.Protocol == diam.ProtocolUnsupportedApplication {
				s.record(batch.input, e.Notification)
			}
			n := e.Notification
			if n.Reply == diam.ProtocolReplyFailed && batch.input.Kind != protocol.WriteResult {
				text := "sm: error answer failed"
				if n.Protocol == diam.ProtocolCERRejected || n.Protocol == diam.ProtocolReplyFailure {
					text = "sm: CEA failed; closing connection"
				}
				err := batch.input.Err
				if err == nil {
					err = fmt.Errorf("required Diameter reply could not be built")
				}
				logMessage(s.conn, batch.input.Message, slog.LevelError, text, err)
			}
			rejectedCER := n.Reply == diam.ProtocolReplyWritten && n.Protocol != diam.ProtocolCERRejected && n.Protocol != diam.ProtocolReplyFailure || n.Reply == diam.ProtocolReplyFailed && (n.Protocol == diam.ProtocolInvalidRequest || n.Protocol == diam.ProtocolUnsupportedAVP)
			if n.Diagnostic == "reject-cer" && n.Closing && rejectedCER && batch.input.Message != nil && batch.input.Message.Header.CommandCode == diam.CapabilitiesExchange {
				logMessage(s.conn, batch.input.Message, slog.LevelWarn, "sm: rejected CER; closing connection", diam.NewProtocolError(n.Protocol, n.ResultCode))
			}
		}
		if e.Kind == protocol.Notify && e.Notification.Kind == protocol.DisconnectNotice {
			s.completeDisconnect(e.Notification)
		}
	}
	for i, e := range batch.effects {
		var observer *acceptedObservation
		if i < len(batch.observers) {
			observer = batch.observers[i]
		}
		switch e.Kind {
		case protocol.RunHook:
			hook := s.sm.cfg.OnDWR
			if e.Message.Header.CommandCode == diam.CapabilitiesExchange {
				hook = s.sm.cfg.OnCER
			}
			if hook != nil {
				hook(s.conn, e.Message)
			}
			s.apply(protocol.Input{Kind: protocol.Continue, Token: e.Token, Message: e.Message, TransportClosed: s.conn.Closed()})
		case protocol.Publish:
			if s.conn.Closed() || s.snapshot().Phase() != protocol.Open {
				continue
			}
			caps := e.Snapshot.Capabilities()
			cer := fromValidatedCER(caps.CER, caps.ParsedApplications)
			meta := smpeer.FromCER(cer)
			s.conn.SetContext(smpeer.NewContext(context.WithValue(s.conn.Context(), advertisedAppsKey{}, caps.LocalApplications), meta))
		case protocol.FreezeAdmission:
			// Every selected Send still receives a terminal writer result when
			// transport closure wins the join, disposing its core-owned pin.
			s.joinWatchdog()
		case protocol.Send:
			s.send(e, batch.input, observer)
		case protocol.ReserveIDs:
			// StateMachine has no shared application ID allocator. The constructor's
			// identifiers retain its existing allocation policy; the core owns them.
			frame := diam.NewRequest(e.Command, 0, s.conn.Dictionary())
			s.apply(protocol.Input{Kind: protocol.ReserveResult, Token: e.Token, Reservation: protocol.Reservation{Token: e.Token, Hop: frame.Header.HopByHopID, End: frame.Header.EndToEndID}})
		case protocol.ReleaseIDs:
			// Logical leases live in the core until the final writer pin is disposed.
		case protocol.HandshakeReady:
			func() {
				defer func() {
					s.sm.registerAcceptedWatchdog(s)
					s.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: e.Token})
				}()
				if s.sm.cfg.OnHandshake != nil {
					metadata, _ := smpeer.FromContext(s.conn.Context())
					s.sm.cfg.OnHandshake(s.conn, metadata)
				}
			}()
		case protocol.Admit:
			m := e.Message
			if m.Header.CommandFlags&diam.RequestFlag == 0 {
				matched := completePendingAnswer(s.conn, m)
				if e.Ownership != 0 && !matched {
					continue
				}
			}
			if h, ok := s.sm.mux.Handler(m); ok {
				h.ServeDIAM(s.conn, m)
			} else {
				s.apply(protocol.Input{Kind: protocol.Unhandled, Message: m})
			}
		case protocol.Hold:
			// Native BeginDispatch retains the handshake barrier. Direct callers can
			// retry after the current callback; no asynchronous application dispatch.
		case protocol.CompleteRequest:
			completePendingAnswer(s.conn, batch.input.Message)
		case protocol.Notify:
			if e.Notification.Protocol == diam.ProtocolDisconnectTimeout {
				in := batch.input
				if e.Message != nil {
					in.Message = e.Message
				}
				s.record(in, e.Notification)
			}
			if e.Notification.Protocol != "" {
				m, n := batch.input.Message, e.Notification
				holdCER := m != nil && m.Header != nil && m.Header.CommandCode == diam.CapabilitiesExchange && batch.input.Error == nil && (n.Protocol == diam.ProtocolCERRejected || n.Protocol == diam.ProtocolReplyFailure || n.Protocol == diam.ProtocolUnexpectedMessage || n.Protocol == diam.ProtocolHandshakeState)
				if !holdCER {
					m.BeginDispatch()()
				}
			}
			observer.call(func() { s.notify(e, batch.input) })
		case protocol.Close:
			if requests := pendingRequests(s.conn); requests != nil {
				requests.CloseAdmission()
			}
			if w := s.watchdogState(); w != nil {
				w.latchStop()
			}
			s.conn.Close()
		}
	}
	for _, next := range batch.following {
		s.run(next)
	}
}

func (s *acceptedHandshake) joinWatchdog() bool {
	w := s.watchdogState()
	if w == nil {
		return true
	}
	joined := make(chan struct{})
	go func() { w.stop(); close(joined) }()
	var closed <-chan struct{}
	if n, ok := diam.ConnAs[diam.CloseNotifier](s.conn); ok {
		closed = n.CloseNotify()
	}
	select {
	case <-joined:
		return !s.conn.Closed()
	case <-closed:
		return !s.conn.Closed()
	}
}

func (s *acceptedHandshake) watchdogState() *acceptedWatchdog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watchdog
}
func (s *acceptedHandshake) emit(event WatchdogEvent) {
	if w := s.watchdogState(); w != nil {
		w.observe(s.conn, event)
	}
}

func (s *acceptedHandshake) notify(e protocol.Effect, in protocol.Input) {
	n := e.Notification
	switch n.Kind {
	case protocol.ProtocolNotice:
		if n.Protocol == "" {
			return
		}

		if s.sm.cfg.OnProtocolError != nil {
			s.sm.HandleProtocolError(diam.ProtocolErrorEvent{Conn: s.conn, Err: diam.NewProtocolError(n.Protocol, n.ResultCode), Message: n.Message, Closing: n.Closing, Reply: n.Reply, ReplyCode: n.ReplyCode})
		}
	case protocol.PeerDisconnectNotice:
		if s.sm.cfg.OnDPR != nil {
			s.sm.cfg.OnDPR(s.conn, DisconnectCause(n.Cause))
		}
	case protocol.WatchdogNotice:
		if n.Diagnostic == "answer" {
			s.emit(WatchdogAnswerReceived)
			return
		}
		if in.Kind != protocol.WriteResult {
			if n.Watchdog == watchdog.Suspect {
				s.emit(WatchdogSuspect)
			} else {
				s.emit(WatchdogRecovered)
			}
		}
	case protocol.DisconnectNotice:
	}
}
