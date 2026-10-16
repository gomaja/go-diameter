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
var fromValidatedCEA = parserbridge.FromValidatedCEA.(func(*base.CEA, []uint32, error) (*smparser.CEA, error))

func (s *acceptedHandshake) run(batch acceptedBatch) {
	var timedHandshake *protocol.Notification
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
					// Stop cancels stale timeout publication, not the committed
					// batch's dispatch, writer-pin or waiter obligations.
					for i, e := range batch.effects {
						if e.Kind == protocol.Close || e.Kind == protocol.Notify && (e.Notification.Protocol == diam.ProtocolWatchdogTimeout || e.Notification.Kind == protocol.WatchdogNotice) {
							batch.effects[i] = protocol.Effect{Kind: protocol.Discard}
						}
					}
				} else {
					w.closing.Add(1)
					defer w.closing.Done()
				}
				w.mu.Unlock()
			}
		}
	}
	// Logs complete before the corresponding Close and observer publication.
	for i, e := range batch.effects {
		var observer *acceptedObservation
		if i < len(batch.observers) {
			observer = batch.observers[i]
		}
		recorded := false
		if s.client != nil && e.Kind == protocol.Notify && e.Notification.Protocol == diam.ProtocolRejectedDWA {
			// Client's rejection warning precedes its invalid-answer callback;
			// malformed DWA diagnostics follow that callback.
			observer.wait()
			s.record(batch.input, e.Notification)
			recorded = true
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
			if batch.input.Kind != protocol.WriteResult && !recorded {
				s.record(batch.input, e.Notification)
			} else if e.Notification.Protocol == diam.ProtocolUnsupportedCommand || e.Notification.Protocol == diam.ProtocolUnsupportedApplication || e.Notification.Diagnostic == "external-reject-cer" && e.Notification.Reply == diam.ProtocolReplyWritten {
				s.record(batch.input, e.Notification)
			}
			n := e.Notification
			if n.Reply == diam.ProtocolReplyFailed && batch.input.Kind != protocol.WriteResult {
				text := "sm: error answer failed"
				if n.Protocol == diam.ProtocolCERRejected || n.Protocol == diam.ProtocolReplyFailure {
					text = "sm: CEA failed; closing connection"
				}
				err := batch.input.Err
				if err == nil && n.Diagnostic == "external-message-error" {
					err = n.CauseError
				}
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
			if s.conn.Closed() || s.phase() != protocol.Open {
				continue
			}
			caps := e.Snapshot.Capabilities()
			var meta *smpeer.Metadata
			if s.client != nil {
				cea, _ := fromValidatedCEA(caps.CEA, caps.ParsedApplications, nil)
				meta = smpeer.FromCEA(cea)
			} else {
				meta = smpeer.FromCER(fromValidatedCER(caps.CER, caps.ParsedApplications))
			}
			ctx := s.conn.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			s.conn.SetContext(smpeer.NewContext(context.WithValue(ctx, advertisedAppsKey{}, caps.LocalApplications), meta))
		case protocol.FreezeAdmission:
			// Every selected Send still receives a terminal writer result when
			// transport closure wins the join, disposing its core-owned pin.
			s.joinWatchdog()
		case protocol.Send:
			s.send(e, batch.input, observer)
		case protocol.ReserveIDs:
			// StateMachine allocates identifiers independently for each control.
			// The core owns each allocation until its release effect.
			frame := diam.NewRequest(e.Command, 0, s.conn.Dictionary())
			s.apply(protocol.Input{Kind: protocol.ReserveResult, Token: e.Token, Reservation: protocol.Reservation{Token: e.Token, Hop: frame.Header.HopByHopID, End: frame.Header.EndToEndID}})
		case protocol.ReleaseIDs:
			// Logical leases live in the core until the final writer pin is disposed.
		case protocol.HandshakeReady:
			func() {
				returned := false
				defer func() {
					if !returned && s.client != nil {
						err := fmt.Errorf("sm: OnHandshake terminated without returning")
						logMessage(s.conn, batch.input.Message, slog.LevelError, "sm: OnHandshake terminated; closing connection", err)
						s.finishHandshake(err)
						s.apply(protocol.Input{Kind: protocol.Abort})
						return
					}
					s.sm.registerAcceptedWatchdog(s)
					s.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: e.Token})
				}()
				if s.sm.cfg.OnHandshake != nil {
					metadata, _ := smpeer.FromContext(s.conn.Context())
					s.sm.cfg.OnHandshake(s.conn, metadata)
				}
				returned = true
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
			if s.client != nil && e.Notification.Kind == protocol.HandshakeNotice && e.Notification.Outcome == protocol.TimedOut {
				// Timeout observers finish before Dial returns, including the
				// protocol observer below.
				notice := e.Notification
				timedHandshake = &notice
				continue
			}
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
	if timedHandshake != nil {
		s.completeHandshake(*timedHandshake, batch.input)
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
	if s.client != nil && in.Error != nil && n.Protocol == diam.ProtocolCEARejected {
		n.Protocol = diam.ProtocolHandshakeState
	}
	switch n.Kind {
	case protocol.HandshakeNotice:
		if s.client != nil {
			s.completeHandshake(n, in)
		}
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
