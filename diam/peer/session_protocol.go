package peer

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/parserbridge"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var protocolInstance atomic.Uint64

var validatedCER = parserbridge.FromValidatedCER.(func(*base.CER, []uint32) *smparser.CER)
var validatedCEA = parserbridge.FromValidatedCEA.(func(*base.CEA, []uint32, error) (*smparser.CEA, error))

func protocolMetadata(snapshot protocol.Snapshot) *smpeer.Metadata {
	caps := snapshot.Capabilities()
	if caps.CER != nil {
		return smpeer.FromCER(validatedCER(caps.CER, caps.ParsedApplications))
	}
	parsed, _ := validatedCEA(caps.CEA, caps.ParsedApplications, nil)
	return smpeer.FromCEA(parsed)
}

// Startup is committed before session registration or worker publication.
// Its effects wait for the actor's dial completion on an initiator leg.
func (s *session) initProtocol() error {
	local := s.m.baseSettings(s.c)
	local.ResolveHostIPAddresses = nil
	role := protocol.Initiator
	if s.inbound {
		role = protocol.Responder
	}
	s.coreID = protocol.Connection{Instance: protocolInstance.Add(1), Generation: s.gen}
	expected := ""
	recovery := false
	if s.actor != nil {
		expected = string(s.actor.cfg.Host)
		if value := s.actor.snapshotValue.Load(); value != nil {
			recovery = value.(PeerSnapshot).Watchdog == WatchdogDown
		}
	}
	core, err := protocol.New(protocol.Config{Connection: s.coreID, Role: role, Local: local,
		Dictionary: s.m.dictionary(), ExpectedHost: expected, TLS: s.c.TLS() != nil, QueueWrites: true,
		HandshakeTimeout: s.m.cfg.Timers.CER, ClosingTimeout: s.m.cfg.Timers.Closing,
		Watchdog: true, WatchdogInterval: max(s.m.cfg.Timers.TwInit, watchdog.MinimumTw), Recovery: recovery,
		CandidateDeadlineOwnedByPeer:         true,
		IgnoreBoundHeaderlessInput:           true,
		InitialNonCERHeaderOnError:           true,
		RejectFatalRepeatedCER:               true,
		ValidateCompletedCEA:                 true,
		PreserveDecoderFatalityOnHeaderError: true,
		ReaderOwnsMessageErrorClosure:        true,
		RetainClosingErrorFatality:           true,
		SeparateHeaderErrorDiagnostics:       true,
		CloseCEROnInvalidHeaderBitsOnly:      true,
		FatalBodyErrorKeepsWatchdogDeadline:  true,
		FatalCEAErrorBeforeCorrelation:       true,
		DWAOwnershipBeforeSemantics:          true,
		DWAIdentityBeforeResult:              true,
		PreserveReplyErrorFormatWrapper:      true,
		AllowAnyLocalDisconnectCause:         true,
		ValidateRequests:                     s.m.cfg.Settings.ValidateRequests, RejectUnknownMandatoryAVPs: s.m.cfg.Settings.RejectUnknownMandatoryAVPs})
	if err != nil {
		return err
	}
	s.core = core
	s.coreTimeouts = make(chan protocol.Input, 1)
	s.coreWrites = make(map[uint64]protocolWrite)
	s.startup = core.Handle(protocol.Input{Kind: protocol.Start, Connection: s.coreID, At: s.m.now(), DeferCER: !s.inbound})
	return nil
}

func (s *session) takeStartup() []protocol.Effect {
	s.coreMu.Lock()
	es := s.startup
	if !s.inbound {
		es = append(es, s.core.Handle(protocol.Input{Kind: protocol.BeginCER, Connection: s.coreID, At: s.m.now()})...)
	}
	es = s.prepareProtocol(es)
	s.startup = nil
	s.coreMu.Unlock()
	return es
}

func (s *session) protocolSnapshot() protocol.Snapshot {
	s.coreMu.Lock()
	defer s.coreMu.Unlock()
	if s.core == nil {
		return protocol.Snapshot{}
	}
	return s.core.Snapshot()
}

func (s *session) postProtocol(in protocol.Input, prior ...*protocolDelivery) {
	var previous *protocolDelivery
	if len(prior) != 0 {
		previous = prior[0]
	}
	if a, gen := s.binding(); a != nil {
		a.post(event{kind: coreEvent, s: s, gen: gen, input: in, replyDelivery: previous})
		// Closure may cross the phase check before this actor enqueue. Tokens
		// make terminal writer disposal idempotent if the actor also drains it.
		if in.Kind == protocol.WriteResult {
			s.terminalProtocol(in)
		}
	} else {
		d := newProtocolDelivery()
		d.priorReply = previous
		s.applyProtocol(in, d)
		d.finish()
		d.deliver(s.m)
	}
}

func (s *session) applyProtocol(in protocol.Input, d *protocolDelivery) {
	in.Connection = s.coreID
	if in.At.IsZero() {
		in.At = s.m.now()
	}
	if a, _ := s.binding(); a != nil {
		in.Interval = a.watchdogInterval()
	}
	if in.Kind == protocol.Receive {
		in.Unhandled = true
		if s.m.matchesPendingAnswer(s, in.Message) {
			in.Ownership = 1
		}
	}
	s.coreMu.Lock()
	// The first DPR obtains its drain snapshot through Frozen. Only later
	// Closing inputs can consume another snapshot; Open traffic never scans
	// Manager's pending request set merely to report protocol activity.
	if in.Kind == protocol.Receive && s.core.Phase() == protocol.Closing {
		in.InFlight = s.protocolInFlight()
	}
	es := s.prepareProtocol(s.handleProtocolLocked(in))
	s.coreMu.Unlock()
	if in.Kind == protocol.ReleaseAdmission {
		if a, _ := s.binding(); a != nil {
			a.syncProtocol(s, in)
		}
	}
	s.runProtocol(in, es, d)
}

// handleProtocolLocked lends one batch its storage until runProtocol returns.
// Nested decisions and concurrent completions obtain independent buffers.
func (s *session) handleProtocolLocked(in protocol.Input) []protocol.Effect {
	buffer := s.coreEffects
	s.coreEffects = s.coreEffectSpare
	s.coreEffectSpare = nil
	return s.core.HandleInto(in, buffer[:0])
}

func (s *session) releaseProtocolEffects(es []protocol.Effect) {
	clear(es[:cap(es)])
	s.coreMu.Lock()
	if cap(es) > cap(s.coreEffects) {
		s.coreEffects, es = es[:0], s.coreEffects
	}
	if cap(es) > cap(s.coreEffectSpare) {
		s.coreEffectSpare = es[:0]
	}
	s.coreMu.Unlock()
}

// Bounded ownership and timer bookkeeping commits with the core decision.
// Callbacks and transport writes execute after coreMu is released.
func (s *session) prepareProtocol(es []protocol.Effect) []protocol.Effect {
	out := es[:0]
	for _, e := range es {
		switch e.Kind {
		case protocol.FreezeAdmission:
			s.m.closeAdmission(s)
			inFlight := s.protocolInFlight()
			out = append(out[:len(out):len(out)], s.prepareProtocol(s.core.Handle(protocol.Input{Kind: protocol.Frozen, Connection: s.coreID, Token: e.Token, InFlight: inFlight}))...)
		case protocol.ArmTimer:
			if old := s.coreTimers[e.Timer]; old != nil {
				old.Stop()
			}
			kind, token, deadline := e.Timer, e.Token, e.Deadline
			s.coreTimers[kind] = s.m.cfg.Clock.AfterFunc(max(0, deadline.Sub(s.m.now())), func() {
				in := protocol.Input{Kind: protocol.TimerExpired, Timer: kind, Token: token, At: maxTime(deadline, s.m.now()), AfterReceive: s.receiveBarrier()}
				if a, _ := s.binding(); a != nil {
					s.postProtocol(in)
				} else {
					select {
					case s.coreTimeouts <- in:
					case <-s.closed:
					}
				}
			})
		case protocol.StopTimer:
			if old := s.coreTimers[e.Timer]; old != nil {
				old.Stop()
				s.coreTimers[e.Timer] = nil
			}
		case protocol.CancelSend:
			s.coreWrites[e.Token].ticket.Cancel()
		case protocol.CompleteRequest:
			// The core owns one exchange per command and has already matched
			// this answer. Only the executor's native writer needs cancelling.
			for _, write := range s.coreWrites {
				if write.command == e.Notification.Message.Header.CommandCode {
					write.ticket.Cancel()
				}
			}
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	return out
}

// Native publication determines whether the outstanding watchdog was sent.
// A local DPR is disconnect control, outside the application drain set.
func (s *session) protocolInFlight() bool {
	if s.beforeInFlightScan != nil {
		s.beforeInFlightScan()
	}
	if s.m.hasInFlightRequests(s) {
		return true
	}
	for _, control := range s.core.Progress().Controls {
		if control.Command != diam.DeviceWatchdog || !control.Logical || control.Answered {
			continue
		}
		if s.requests == nil {
			return true
		}
		return s.requests.MatchAnswer(&diam.Message{Header: &diam.Header{CommandCode: diam.DeviceWatchdog, HopByHopID: control.Reservation.Hop, EndToEndID: control.Reservation.End}}, false)
	}
	return false
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (s *session) runProtocol(in protocol.Input, es []protocol.Effect, d *protocolDelivery) {
	defer s.releaseProtocolEffects(es)
	if d == nil {
		d = newProtocolDelivery()
		defer func() { d.finish(); d.deliver(s.m) }()
	}
	a, _ := s.binding()
	// Diagnostics precede transport closure and observer publication.
	for _, e := range es {
		if e.Kind == protocol.Notify && e.Notification.Kind == protocol.HandshakeNotice && in.Kind == protocol.ReserveResult && e.Notification.Handshake.Err() != nil && a != nil && a.i == s {
			a.failLocal("build CER", e.Notification.Handshake.Err())
		}
		if e.Kind == protocol.Notify && in.Kind != protocol.WriteResult {
			s.recordProtocol(in, e.Notification)
		}
	}
	for _, e := range es {
		switch e.Kind {
		case protocol.ReserveIDs:
			s.m.pendingMu.Lock()
			hop := s.m.nextHopIDLocked(s, 0, false)
			if s.m.controls[s] == nil {
				s.m.controls[s] = make(map[uint32]struct{})
			}
			s.m.controls[s][hop] = struct{}{}
			s.m.pendingMu.Unlock()
			end := s.m.endToEnd.allocate()
			s.applyProtocol(protocol.Input{Kind: protocol.ReserveResult, Token: e.Token, Reservation: protocol.Reservation{Token: e.Token, Hop: hop, End: end}}, d)
		case protocol.ReleaseIDs:
			s.releaseControl(e.Reservation.Hop)
		case protocol.Send:
			s.sendProtocol(e, in, d)
		case protocol.ValidatedCER:
			s.cerRequest = in.Message
			s.meta = protocolMetadata(*e.Snapshot)
			if a == nil {
				s.m.mu.RLock()
				a = s.m.peers[identity(s.meta.OriginHost)]
				s.m.mu.RUnlock()
				if a == nil {
					s.m.report(s, in.Message, fmt.Errorf("peer: unknown Origin-Host %s", s.meta.OriginHost))
					s.applyProtocol(protocol.Input{Kind: protocol.RejectCandidate, Token: e.Token, ResultCode: diam.UnknownPeer, Message: in.Message}, d)
					continue
				}
				if !s.bind(a, 0) {
					continue
				}
				a.commit(event{kind: rConnCER, s: s, msg: in.Message, meta: s.meta.Clone(), receivedAt: in.At, receiveSequence: in.Sequence}, d)
				return
			} else {
				a.onCER(event{s: s, msg: in.Message, meta: s.meta.Clone()})
			}
		case protocol.Publish:
			if s.isRetired() {
				continue
			}
			s.meta = protocolMetadata(*e.Snapshot)
			if a != nil {
				a.meta = s.meta.Clone()
			}
		case protocol.HandshakeReady:
			if a == nil || s.isRetired() {
				continue
			}
			if !s.inbound {
				if err := a.admitDiscovery(s, s.meta); err != nil {
					a.fail(err)
					continue
				}
				a.openInitiator(s)
				s.applyProtocol(protocol.Input{Kind: protocol.ReleaseAdmission, Token: e.Token}, d)
				if a.state == IOpen {
					a.everOpen = true
					a.publish(nil)
				}
			} else {
				s.applyProtocol(protocol.Input{Kind: protocol.ReleaseAdmission, Token: e.Token}, d)
			}
		case protocol.Admit:
			if s.isRetired() {
				continue
			}
			if e.Ownership != 0 {
				s.m.receiveClosingAnswer(s, e.Message)
			} else {
				s.m.receiveAnswer(s, e.Message, d)
			}
		case protocol.CompleteRequest:
			if s.requests != nil {
				s.requests.MatchAnswer(&diam.Message{Header: &e.Notification.Message.Header}, true)
			}
		case protocol.PeerDisconnectDecision:
			if a != nil && a.active == s {
				a.suppressReconnect = e.Cause == 1 || e.Cause == 2
			}
		case protocol.Close:
			if a != nil && a.active == s {
				for _, notice := range es {
					if notice.Kind == protocol.Notify && notice.Notification.Kind == protocol.DisconnectNotice && notice.Notification.Outcome == protocol.Completed {
						if s == a.i {
							a.step(iDPA, s, in.Message)
						} else {
							a.step(rDPA, s, in.Message)
						}
						break
					}
				}
			}
			s.close()
		case protocol.Notify:
			s.notifyProtocol(in, e.Notification, d)
		}
	}
	if a != nil && (a.i == s || a.r == s || a.active == s) {
		a.syncProtocol(s, in)
	}
}

func (s *session) sendProtocol(e protocol.Effect, in protocol.Input, d *protocolDelivery) {
	m := e.Message
	if e.Notification.Protocol != "" {
		s.recordProtocol(in, e.Notification)
	}
	var ticket *diam.RequestWrite
	if m.Header.CommandFlags&diam.RequestFlag != 0 && s.requests != nil {
		ticket = s.requests.PrepareWrite(m.Header)
	}
	s.coreMu.Lock()
	s.coreWrites[e.Token] = protocolWrite{ticket: ticket, command: m.Header.CommandCode}
	s.coreMu.Unlock()
	w := writeRequest{msg: m, required: e.Required, closeAfter: e.CloseAfter, protocolToken: e.Token, protocolSource: in, replyDelivery: d}
	if e.Required && s.m.ProtocolErrorEnabled() {
		w.reply = requiredReplyEvent(s.c, in.Message, answerCode(m))
	}
	err := s.sendWrite(w)
	if err != nil {
		if a, _ := s.binding(); a != nil && (a.i == s || a.r == s || a.active == s) && e.Notification.Protocol == "" {
			// Handle commits the failed queue decision before the peer-level
			// failure closes its other election leg.
			s.coreMu.Lock()
			es := s.prepareProtocol(s.core.Handle(protocol.Input{Kind: protocol.WriteResult, Connection: s.coreID, Token: e.Token, Stage: protocol.QueueStage, ReplyCode: answerCode(m), Err: err}))
			s.coreMu.Unlock()
			a.failLocal("send "+controlName(m), err)
			s.runProtocol(protocol.Input{Kind: protocol.WriteResult, Stage: protocol.QueueStage, Err: err, Message: in.Message}, es, d)
			s.finishProtocolWriter(w, protocol.SkippedStage, 0, err)
			return
		}
		text := "peer: request rejection answer failed"
		if in.Error != nil {
			text = "peer: error answer failed; closing connection"
		}
		if e.Notification.Protocol == diam.ProtocolCERRejected {
			text = "peer: send rejected CER answer failed; closing connection"
		}
		if e.Notification.Protocol == diam.ProtocolUnsupportedCommand || e.Notification.Protocol == diam.ProtocolUnsupportedApplication {
			text = "peer: unsupported request answer failed"
		}
		s.m.reportLocal(s, in.Message, text, err)
	}
	s.applyProtocol(protocol.Input{Kind: protocol.WriteResult, Token: e.Token, Stage: protocol.QueueStage, ReplyCode: answerCode(m), Err: err, Message: in.Message, Error: in.Error}, d)
	if err != nil {
		s.finishProtocolWriter(w, protocol.SkippedStage, 0, err)
	}
}

func answerCode(m *diam.Message) uint32 {
	if m.Header.CommandFlags&diam.RequestFlag != 0 {
		return 0
	}
	if field, err := m.FindAVP(avp.ResultCode, 0); err == nil {
		if value, ok := field.Data.(datatype.Unsigned32); ok {
			return uint32(value)
		}
	}
	return 0
}
func controlName(m *diam.Message) string {
	if m == nil || m.Header == nil {
		return "reply"
	}
	req := m.Header.CommandFlags&diam.RequestFlag != 0
	switch m.Header.CommandCode {
	case diam.CapabilitiesExchange:
		if req {
			return "CER"
		}
		return "CEA"
	case diam.DeviceWatchdog:
		if req {
			return "DWR"
		}
		return "DWA"
	case diam.DisconnectPeer:
		if req {
			return "DPR"
		}
		return "DPA"
	}
	return "reply"
}

func (s *session) finishProtocolWriter(w writeRequest, stage protocol.WriteStage, n int64, err error) {
	in := protocol.Input{Kind: protocol.WriteResult, Connection: s.coreID, Token: w.protocolToken, Stage: stage, Bytes: n, ExpectedBytes: int64(w.msg.Len()), ReplyCode: answerCode(w.msg), Err: err, Message: w.protocolSource.Message, Error: w.protocolSource.Error}
	s.coreMu.Lock()
	ticket := s.coreWrites[w.protocolToken].ticket
	delete(s.coreWrites, w.protocolToken)
	completed := s.core.CompleteQueuedReply(in)
	s.coreMu.Unlock()
	ticket.Release()
	if completed {
		return
	}
	if s.terminalProtocol(in) {
		return
	}
	s.postProtocol(in, w.replyDelivery)
}

func (s *session) writeProtocol(w writeRequest) bool {
	stage := protocol.WrittenStage
	var n int64
	var err error
	if s.beforePublication != nil {
		s.beforePublication(w.msg)
	}
	probe := w.msg.Header.CommandCode == diam.DeviceWatchdog && w.msg.Header.CommandFlags&diam.RequestFlag != 0
	if s.isRetired() || s.c.Closed() || probe && s.closing.Load() || !s.leaseAllowsWrite(w) {
		stage, err = protocol.SkippedStage, diam.ErrConnectionRetired
	} else {
		n, err = w.msg.WriteTo(s.c)
		if n == 0 && (errors.Is(err, diam.ErrConnectionClosing) || errors.Is(err, diam.ErrConnectionRetired) || errors.Is(err, diam.ErrRequestCompleted)) {
			stage = protocol.SkippedStage
		}
		if err == nil && n != int64(w.msg.Len()) {
			err = io.ErrShortWrite
		}
	}
	if err != nil && stage != protocol.SkippedStage {
		s.m.reportLocal(s, w.msg, "peer: write failed; closing connection", err)
	}
	// Queue feedback commits before a concurrent writer reports completion.
	// Reporting can remain blocked independently of timers and retirement.
	if w.replyDelivery != nil {
		<-w.replyDelivery.done
	}
	s.finishProtocolWriter(w, stage, n, err)
	if err != nil && stage == protocol.WrittenStage && w.reply != nil {
		w.replyDelivery.replyFailed(s.m, w.reply)
	}
	if err != nil && stage != protocol.SkippedStage || w.closeAfter && err == nil {
		s.close()
		return true
	}
	return false
}

func (a *actor) syncProtocol(s *session, in protocol.Input) {
	if a.active != s {
		return
	}
	s.coreMu.Lock()
	progress := s.core.Progress()
	s.coreMu.Unlock()
	wd := progress.Watchdog
	if progress.Phase == protocol.Closing && a.state != Closing {
		a.stopTimer()
		a.state = Closing
		a.publish(nil)
	}
	if progress.Phase >= protocol.Closed {
		return
	}
	if progress.Ready && s.inbound {
		s.admitted.Store(true)
	}
	if a.publishedWatchdog() != WatchdogState(wd.State) {
		reason := "peer: traffic restored watchdog health"
		if !a.everOpen {
			reason = "peer: initial connection established"
		}
		if wd.State == watchdog.Suspect {
			reason = "peer: unanswered DWR"
		}
		if wd.State == watchdog.Reopen {
			reason = "peer: recovered connection awaiting three DWA"
		}
		if wd.State == watchdog.Okay && a.publishedWatchdog() == WatchdogReopen {
			reason = "peer: three valid recovery DWA"
		}
		if in.Kind == protocol.Receive && in.Message != nil && in.Message.Header.CommandCode == diam.DeviceWatchdog && in.Message.Header.CommandFlags&diam.RequestFlag == 0 && a.publishedWatchdog() != WatchdogReopen {
			reason = "peer: valid DWA restored watchdog health"
		}
		a.publishWatchdog(WatchdogState(wd.State), errors.New(reason))
		if wd.State == watchdog.Okay {
			a.failures = 0
		}
	}
}

func (s *session) recordProtocol(in protocol.Input, n protocol.Notification) {
	if n.Protocol == "" {
		return
	}
	a, _ := s.binding()
	msg := in.Message
	if msg == nil && n.Message.HasHeader {
		msg = &diam.Message{Header: &n.Message.Header}
	}
	err := n.CauseError
	if err == nil {
		err = diam.NewProtocolError(n.Protocol, n.ResultCode)
	}
	if n.ReplyError != nil {
		text := "peer: request rejection answer failed"
		switch {
		case in.ErrorInput:
			text = "peer: error answer failed; closing connection"
		case n.Protocol == diam.ProtocolCERRejected:
			text = "peer: build rejected CER answer failed; closing connection"
		case n.Diagnostic == "unhandled":
			if msg != nil {
				s.m.report(s, msg, fmt.Errorf("peer: unhandled message %d/%d", msg.Header.ApplicationID, msg.Header.CommandCode))
			}
			text = "peer: unsupported request answer failed"
		default:
			if n.CauseError != nil {
				s.m.report(s, msg, n.CauseError)
			}
		}
		s.m.reportLocal(s, msg, text, n.ReplyError)
		return
	}
	if n.Protocol == diam.ProtocolReplyFailure && n.CauseError != nil && in.Kind == protocol.Activate && a != nil {
		a.failLocal("build CEA", n.CauseError)
		return
	}
	if n.Protocol == diam.ProtocolHandshakeTimeout && a == nil {
		err = errors.New("peer: pre-CER timeout")
	}
	if n.Protocol == diam.ProtocolHandshakeState && (a == nil || a.i != s) {
		if a == nil {
			if in.ErrorInput {
				err = fmt.Errorf("peer: malformed pre-CER message; closing connection: %w", err)
			} else {
				err = errors.New("peer: first inbound message is not CER")
			}
		} else if !in.ErrorInput {
			text := "peer: message before handshake"
			if a.state == WaitICEA || a.state == WaitReturns {
				text = "peer: message before answering connection handshake"
			}
			err = errors.New(text)
		}
		s.m.report(s, msg, err)
		return
	}
	if n.Diagnostic == "header-error" || n.Diagnostic == "reject-cer-header" {
		s.m.report(s, msg, err)
		if n.Diagnostic == "header-error" {
			return
		}
	}
	if n.Diagnostic == "external-reject-cer" || n.Diagnostic == "reject-cer-header" {
		s.m.report(s, msg, fmt.Errorf("peer: invalid CER rejected; closing connection: %w", err))
		return
	}
	if n.Diagnostic == "external-message-error" {
		if n.Reply == diam.ProtocolReplyFailed && n.CauseError != nil {
			s.m.reportLocal(s, msg, "peer: error answer failed; closing connection", err)
		}
		return
	}
	if n.Diagnostic == "unhandled" && msg != nil {
		s.m.report(s, msg, fmt.Errorf("peer: unhandled message %d/%d", msg.Header.ApplicationID, msg.Header.CommandCode))
		return
	}
	if n.Protocol == diam.ProtocolCERRejected && n.CauseError == nil {
		return
	}
	if n.CauseError == nil && (n.Protocol == diam.ProtocolInvalidRequest || n.Protocol == diam.ProtocolUnsupportedAVP || n.Protocol == diam.ProtocolUnsupportedApplication) {
		return
	}
	if n.Protocol == diam.ProtocolMalformedMessage && in.ErrorInput && n.Diagnostic != "reject-cer" {
		return
	}
	if n.Diagnostic == "reject-cer" && in.ErrorInput && in.Error != nil {
		s.m.report(s, msg, fmt.Errorf("peer: malformed CER rejected; closing connection: %w", err))
		return
	}
	pendingCEAHeader := n.Protocol == diam.ProtocolInvalidHeader && a != nil && a.i == s && (a.state == WaitICEA || a.state == WaitReturns)
	if (n.Protocol == diam.ProtocolCEARejected || pendingCEAHeader) && a != nil && a.i == s {
		semantic := s.protocolSnapshot().Handshake()
		if semantic.Err() != nil {
			_, err = validatedCEA(semantic.CEA(), nil, semantic.Err())
		}
	}
	if n.Protocol == diam.ProtocolRejectedDWA {
		err = &dwaResultCodeError{result: n.ResultCode}
	}
	if n.Protocol == diam.ProtocolPeerRejected && msg != nil && msg.Header.CommandCode == diam.DisconnectPeer {
		err = fmt.Errorf("peer: DPA Result-Code %d", n.ResultCode)
	}
	if n.Protocol == diam.ProtocolUnexpectedMessage && msg != nil && msg.Header.CommandFlags&diam.RequestFlag == 0 {
		switch msg.Header.CommandCode {
		case diam.CapabilitiesExchange:
			if a != nil && a.i == s && (a.state == WaitICEA || a.state == WaitReturns) {
				err = errors.New("peer: CEA identifiers mismatch")
			} else {
				err = s.unmatchedProtocolAnswer(msg)
			}
		case diam.DeviceWatchdog:
			err = errors.New("peer: unsolicited or mismatched DWA")
		case diam.DisconnectPeer:
			switch n.Diagnostic {
			case "dpa-host":
				err = errors.New("peer: DPA Origin-Host mismatch")
			default:
				if s.closing.Load() {
					err = errors.New("peer: DPA identifiers mismatch")
				} else {
					err = s.unmatchedProtocolAnswer(msg)
				}
			}
		}
	}
	switch err.Error() {
	case "DWR Origin-Host does not match the admitted peer (RFC 6733 §6.3)":
		err = errors.New("peer: DWR Origin-Host mismatch")
	case "DPR Origin-Host does not match the admitted peer (RFC 6733 §6.3)":
		err = errors.New("peer: DPR Origin-Host mismatch")
	case "DWA Origin-Host mismatch":
		err = errors.New("peer: DWA Origin-Host mismatch")
	case "DWA Origin-Realm mismatch":
		err = errors.New("peer: DWA Origin-Realm mismatch")
	}
	if a != nil && (a.i == s || a.active == s) && n.Closing && (n.Protocol == diam.ProtocolCEARejected || pendingCEAHeader || n.Protocol == diam.ProtocolHandshakeTimeout || n.Protocol == diam.ProtocolHandshakeState || n.Protocol == diam.ProtocolWatchdogTimeout || n.Protocol == diam.ProtocolDisconnectTimeout) {
		switch n.Protocol {
		case diam.ProtocolCEARejected, diam.ProtocolInvalidHeader:
			if in.ErrorInput {
				err = errors.New("peer: non-CEA before handshake")
			} else if errors.Is(err, protocol.ErrUnexpectedPeer) {
				err = errors.New("peer: CEA Origin-Host mismatch")
			} else {
				err = fmt.Errorf("peer: invalid CEA: %w", err)
			}
		case diam.ProtocolHandshakeTimeout, diam.ProtocolDisconnectTimeout:
			err = errors.New("peer: state timeout")
		case diam.ProtocolHandshakeState:
			err = errors.New("peer: non-CEA before handshake")
		case diam.ProtocolWatchdogTimeout:
			err = errors.New("peer: watchdog suspect timeout")
			if a.publishedWatchdog() == WatchdogReopen {
				err = errors.New("peer: recovery DWR unanswered")
			}
		}
		a.fail(err)
	} else {
		if n.Protocol == diam.ProtocolUnexpectedMessage && msg != nil && msg.Header.CommandCode == diam.CapabilitiesExchange && msg.Header.CommandFlags&diam.RequestFlag != 0 {
			err = errors.New("peer: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible")
			s.m.reportFailure(s, msg, slog.LevelWarn, err.Error(), err)
		} else {
			s.m.report(s, msg, err)
		}
	}
}

// Application ownership remains with Manager; the core has already discarded
// this control answer. Preserve the shared reservation space's diagnostic.
func (s *session) unmatchedProtocolAnswer(msg *diam.Message) error {
	s.m.pendingMu.Lock()
	p := s.m.pending[s][msg.Header.HopByHopID]
	unmatched := p == nil || p.done
	s.m.pendingMu.Unlock()
	if unmatched {
		return errors.New("peer: unmatched answer (RFC 6733 §6.2.1)")
	}
	return errors.New("peer: unmatched or mismatched answer (RFC 6733 §6.2.1)")
}

func (s *session) notifyProtocol(in protocol.Input, n protocol.Notification, d *protocolDelivery) {
	if n.Protocol == "" {
		return
	}
	if in.Kind == protocol.WriteResult && in.Stage == protocol.WrittenStage && in.Err != nil && n.Protocol == diam.ProtocolReplyFailure {
		return
	}
	msg := in.Message
	if msg == nil && n.Message.HasHeader {
		msg = &diam.Message{Header: &n.Message.Header}
	}
	kind := n.Protocol
	if in.ErrorInput && kind == diam.ProtocolCEARejected {
		kind = diam.ProtocolHandshakeState
	}
	if kind == diam.ProtocolUnexpectedMessage && msg != nil && msg.Header.CommandCode == diam.DeviceWatchdog {
		kind = diam.ProtocolInvalidDWA
	}
	if kind == diam.ProtocolUnexpectedMessage && msg != nil && msg.Header.CommandCode == diam.DisconnectPeer {
		if s.closing.Load() {
			kind = diam.ProtocolInvalidDPA
		}
	}
	if s.m.ProtocolErrorEnabled() {
		d.notifications = append(d.notifications, diam.ProtocolErrorEvent{Conn: s.c, Err: diam.NewProtocolError(kind, n.ResultCode), Message: n.Message, Closing: n.Closing, Reply: n.Reply, ReplyCode: n.ReplyCode})
	}
}

// abortProtocol settles local shutdown before workers observe s.closed. Abort's
// Close effect is fulfilled by closeWithFailover after releasing coreMu; its
// handshake/disconnect notices are internal completion obligations. The existing
// executor commits timer stops and native cancellation under the protocol lock.
func (s *session) abortProtocol() {
	s.coreMu.Lock()
	if s.core == nil {
		s.coreMu.Unlock()
		return
	}
	if s.requests != nil {
		s.requests.CloseAdmission()
		for _, control := range s.core.Progress().Controls {
			if control.Command != 0 {
				s.requests.MatchAnswer(&diam.Message{Header: &diam.Header{CommandCode: control.Command, HopByHopID: control.Reservation.Hop, EndToEndID: control.Reservation.End}}, true)
			}
		}
	}
	es := s.prepareProtocol(s.core.Handle(protocol.Input{Kind: protocol.Abort, Connection: s.coreID, At: s.m.now()}))
	s.coreMu.Unlock()
	for _, e := range es {
		if e.Kind == protocol.ReleaseIDs {
			s.releaseControl(e.Reservation.Hop)
		}
	}
	s.releaseProtocolEffects(es)
}

// terminalProtocol preserves selected-writer disposal after actor shutdown. A
// terminal core can only release these control IDs; it cannot publish callbacks
// or revive peer state. Repeated completion for the same token is harmless.
func (s *session) terminalProtocol(in protocol.Input) bool {
	s.coreMu.Lock()
	if s.core == nil || s.core.Phase() < protocol.Closed {
		s.coreMu.Unlock()
		return false
	}
	in.Connection = s.coreID
	es := s.handleProtocolLocked(in)
	s.coreMu.Unlock()
	for _, e := range es {
		if e.Kind == protocol.ReleaseIDs {
			s.releaseControl(e.Reservation.Hop)
		}
	}
	s.releaseProtocolEffects(es)
	return true
}
