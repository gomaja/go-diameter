package sm

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

var acceptedInstance atomic.Uint64

// contextCoreKey keys the core of a Conn that exposes no lifecycle signal.
// Nothing reports such a Conn's closure, so its core lives in the Conn's own
// context, like the peer metadata: callbacks still queued after Closed keep
// their admission state, and the core goes away with the Conn.
type contextCoreKey struct{ sm *StateMachine }

// acceptedHandshake serializes one generation's core. It owns execution only:
// sockets, timers, native write tickets and callbacks never enter the core.
// RFC 6733 §§5.3–5.6; RFC 3539 §3.4.1 and Appendix A.
type acceptedHandshake struct {
	mu                sync.Mutex
	core              *protocol.Core
	sm                *StateMachine
	conn              diam.Conn
	id                protocol.Connection
	sequence          uint64
	timers            [protocol.ReceiverDisconnectTimer + 1]*time.Timer
	timer             *time.Timer // handshake timer, retained for lifecycle inspection
	waiter            chan error
	waiterToken       uint64
	held              []protocol.Input
	writes            map[uint64]*diam.RequestWrite
	writeHeaders      map[uint64]diam.Header
	watchdog          *acceptedWatchdog
	observerTail      <-chan struct{}
	client            *Client
	handshake         chan error
	handshakeDone     chan struct{}
	handshakeOnce     sync.Once
	handshakeTimedOut bool
	policy            *watchdogPolicy
	initialCERDone    bool
	initialCERErr     error
}

type acceptedObservation struct {
	previous <-chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (o *acceptedObservation) wait() {
	if o != nil && o.previous != nil {
		<-o.previous
	}
}
func (o *acceptedObservation) finish() {
	if o != nil {
		o.once.Do(func() { close(o.done) })
	}
}
func (o *acceptedObservation) call(fn func()) { o.wait(); defer o.finish(); fn() }

type acceptedBatch struct {
	effects         []protocol.Effect
	input           protocol.Input
	releaseDispatch bool
	observers       []*acceptedObservation
	following       []acceptedBatch
}

func (sm *StateMachine) acceptedCore(c diam.Conn, m *diam.Message, create bool) *acceptedHandshake {
	return sm.acceptedCoreWithAdmission(c, m, create, m != nil)
}

func (sm *StateMachine) acceptedCoreWithAdmission(c diam.Conn, m *diam.Message, create, adopt bool) *acceptedHandshake {
	if value, ok := sm.cores.Load(c); ok {
		return value.(*acceptedHandshake)
	}
	if state := sm.contextCore(c); state != nil {
		return state
	}
	if !create || c.Closed() {
		return nil
	}
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok && lifecycle.RetirementReason() != 0 {
		return nil
	}
	var peer *protocol.PeerClaims
	if adopt {
		peer = externalPeerClaims(c)
	}
	state := &acceptedHandshake{sm: sm, conn: c, id: protocol.Connection{Instance: acceptedInstance.Add(1), Generation: connectionGeneration(c)}, writes: make(map[uint64]*diam.RequestWrite)}
	cfg := sm.capabilities(c, m)
	d := sm.cfg.HandshakeTimeout
	if d < 0 {
		d = 0
	} else if d == 0 {
		d = DefaultHandshakeTimeout
	}
	// Opaque wrappers still gate CER, but cannot start an accept deadline.
	if m != nil {
		d = 0
	}
	interval := watchdog.DefaultTw
	if sm.watchdog != nil {
		interval = max(sm.watchdog.twinit, watchdog.MinimumTw)
	}
	closingTimeout := sm.receiverCloseTimeout()
	if _, ok := diam.ConnAs[diam.CloseNotifier](c); !ok {
		closingTimeout = 0
	}
	coreConfig := protocol.Config{Connection: state.id, Role: protocol.Responder,
		Local: cfg, Dictionary: sm.capabilityDictionary(c, m), TLS: c.TLS() != nil,
		Hooks: true, HandshakeTimeout: d, ClosingTimeout: closingTimeout,
		LocalDisconnectInClosing: true,
		DWRHookCompatibility:     true,
		Watchdog:                 sm.watchdog != nil, WatchdogInterval: interval,
		ValidateRequests: sm.cfg.ValidateRequests, RejectUnknownMandatoryAVPs: sm.cfg.RejectUnknownMandatoryAVPs}
	var core *protocol.Core
	var err error
	if peer != nil {
		core, err = protocol.NewAdmitted(coreConfig, *peer)
	} else {
		core, err = protocol.New(coreConfig)
	}
	if err != nil {
		logMessage(c, m, slog.LevelError, "sm: protocol initialization failed; closing connection", err)
		c.Close()
		return nil
	}
	state.core = core
	state.policy = sm.watchdog
	var done <-chan struct{}
	if m != nil || peer != nil {
		if done = connectionDone(c); done == nil {
			return sm.storeContextCore(c, state)
		}
	}
	actual, loaded := sm.cores.LoadOrStore(c, state)
	if loaded {
		return actual.(*acceptedHandshake)
	}
	state.apply(protocol.Input{Kind: protocol.Start})
	if done != nil {
		go func() {
			<-done
			state.apply(protocol.Input{Kind: protocol.TransportLost})
			sm.cores.CompareAndDelete(c, state)
		}()
	}
	return state
}

// externalPeerClaims reads only the connection's saved offer. Deriving an offer
// from current settings would change validation for manually admitted peers.
func externalPeerClaims(c diam.Conn) *protocol.PeerClaims {
	ctx := c.Context()
	if ctx == nil {
		return nil
	}
	metadata, ok := smpeer.FromContext(ctx)
	if !ok || metadata == nil {
		return nil
	}
	local, _ := ctx.Value(advertisedAppsKey{}).([]uint32)
	return &protocol.PeerClaims{Host: string(metadata.OriginHost), Realm: string(metadata.OriginRealm),
		LocalApplications: local, RemoteApplications: metadata.Applications, CER: metadata.CEA == nil}
}

func (s *acceptedHandshake) passiveResponder() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.PassiveResponder()
}

func (sm *StateMachine) contextCore(c diam.Conn) *acceptedHandshake {
	if ctx := c.Context(); ctx != nil {
		state, _ := ctx.Value(contextCoreKey{sm}).(*acceptedHandshake)
		return state
	}
	return nil
}

// storeContextCore publishes the first core for a Conn without a lifecycle
// signal; concurrent first messages share it.
func (sm *StateMachine) storeContextCore(c diam.Conn, state *acceptedHandshake) *acceptedHandshake {
	sm.contextCores.Lock()
	if existing := sm.contextCore(c); existing != nil {
		sm.contextCores.Unlock()
		return existing
	}
	ctx := c.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	c.SetContext(context.WithValue(ctx, contextCoreKey{sm}, state))
	sm.contextCores.Unlock()
	state.apply(protocol.Input{Kind: protocol.Start})
	return state
}

func (sm *StateMachine) receiverCloseTimeout() time.Duration {
	if sm.cfg.DPRCloseTimeout > 0 {
		return sm.cfg.DPRCloseTimeout
	}
	return 5 * time.Second
}

func (s *acceptedHandshake) snapshot() protocol.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Snapshot()
}

func (s *acceptedHandshake) prepare(in protocol.Input) acceptedBatch {
	if (in.Kind == protocol.Receive || in.Kind == protocol.Continue) && len(s.sm.cfg.HostIPAddresses) == 0 && s.phase() == protocol.PreCER {
		in.RefreshLocalAddresses = true
		in.LocalAddresses, in.Err = getLocalAddresses(s.conn)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core.PassiveResponder() && (in.Kind == protocol.Receive || in.Kind == protocol.Continue || in.Kind == protocol.Disconnect) {
		s.core.RefreshAdmission(externalPeerClaims(s.conn))
	}
	in.Connection = s.id
	if in.At.IsZero() {
		in.At = time.Now()
	}
	if s.policy != nil {
		in.Interval = jitteredTw(s.policy.twinit, s.policy.jitter)
	}
	if in.Kind == protocol.Receive {
		s.sequence++
		in.Sequence = s.sequence
		if in.Message != nil {
			_, found := s.sm.mux.Handler(in.Message)
			in.Unhandled = !found
			in.HasHandler = found
		}
		if requests := pendingRequests(s.conn); requests != nil {
			if requests.MatchAnswer(in.Message, false) {
				in.Ownership = s.sequence
			}
			in.InFlight = requests.HasPending()
		}
	}
	batch := s.batchLocked(in, s.core.Handle(in))
	if in.Kind == protocol.ReleaseAdmission && s.core.Ready() {
		held := s.held
		s.held = nil
		for _, saved := range held {
			batch.following = append(batch.following, s.batchLocked(saved, s.core.Handle(saved)))
		}
	}
	return batch
}

func (s *acceptedHandshake) batchLocked(in protocol.Input, effects []protocol.Effect) acceptedBatch {
	batch := acceptedBatch{input: in}
	batch.effects = s.prepareLocked(effects, &batch.releaseDispatch)
	for i, e := range batch.effects {
		if s.client != nil && e.Kind == protocol.Notify && e.Notification.Kind == protocol.HandshakeNotice && e.Notification.Outcome == protocol.TimedOut {
			// Delivery belongs to the committed timeout, including when caller
			// cancellation arrives while its synchronous observer is running.
			s.handshakeTimedOut = true
		}
		observe := e.Kind == protocol.Send && e.Message.Header.CommandCode == diam.DeviceWatchdog && e.Message.Header.CommandFlags&diam.RequestFlag != 0 ||

			e.Kind == protocol.Notify && (e.Notification.Kind == protocol.WatchdogNotice && in.Kind != protocol.WriteResult || e.Notification.Protocol == diam.ProtocolInvalidDWA || e.Notification.Protocol == diam.ProtocolRejectedDWA || e.Notification.Protocol == diam.ProtocolWatchdogTimeout)
		if observe {
			if batch.observers == nil {
				batch.observers = make([]*acceptedObservation, len(batch.effects))
			}
			o := &acceptedObservation{previous: s.observerTail, done: make(chan struct{})}
			s.observerTail = o.done
			batch.observers[i] = o
		}
	}
	return batch
}

// Freeze is acknowledged under the same admission mutex as Closing. Timer
// installation is bounded bookkeeping; every callback/write runs after unlock.
// The input effects belong to this batch. Compact consumed bookkeeping in
// place; recursive expansion must detach before overwriting unread effects.
func (s *acceptedHandshake) prepareLocked(effects []protocol.Effect, releaseDispatch *bool) []protocol.Effect {
	out := effects[:0]
	for _, e := range effects {
		// Admission release is an obligation of the committed input, including
		// effects consumed here. Execute it only after the mutex is unlocked.
		*releaseDispatch = *releaseDispatch || e.ReleaseDispatch
		switch e.Kind {
		case protocol.ValidatedCER:
			out = append(out[:len(out):len(out)], s.prepareLocked(s.core.Handle(protocol.Input{Kind: protocol.Activate, Connection: s.id, Token: e.Token}), releaseDispatch)...)
		case protocol.FreezeAdmission:
			inFlight := false
			if requests := pendingRequests(s.conn); requests != nil {
				requests.CloseAdmission()
				inFlight = requests.HasPending()
			}
			if s.watchdog != nil {
				s.watchdog.latchStop()
			}
			out = append(out, e)
			out = append(out[:len(out):len(out)], s.prepareLocked(s.core.Handle(protocol.Input{Kind: protocol.Frozen, Connection: s.id, Token: e.Token, InFlight: inFlight}), releaseDispatch)...)
		case protocol.ArmTimer:
			if e.Timer == protocol.WatchdogTimer && s.watchdog == nil {
				continue
			}
			if timer := s.timers[e.Timer]; timer != nil {
				timer.Stop()
			}
			timerKind, token := e.Timer, e.Token
			s.timers[timerKind] = time.AfterFunc(time.Until(e.Deadline), func() { s.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: timerKind, Token: token}) })
			if e.Timer == protocol.HandshakeTimer {
				s.timer = s.timers[e.Timer]
			}
		case protocol.StopTimer:
			if timer := s.timers[e.Timer]; timer != nil {
				timer.Stop()
			}
		case protocol.Hold:
			s.held = append(s.held, e.Input)
		case protocol.CancelSend:
			if ticket := s.writes[e.Token]; ticket != nil {
				ticket.Cancel()
			}
		case protocol.CompleteRequest:
			// Complete logical ownership before a selected writer acquires
			// the native gate. Its pin remains until the writer exits (§6.2.1).
			m := inMessageForCompletion(e)
			if m != nil {
				for token, h := range s.writeHeaders {
					if h.CommandCode == m.CommandCode && h.ApplicationID == m.ApplicationID && h.HopByHopID == m.HopByHopID && h.EndToEndID == m.EndToEndID {
						s.writes[token].Cancel()
					}
				}
			}
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	return out
}

func inMessageForCompletion(e protocol.Effect) *diam.Header {
	if e.Notification.Message.HasHeader {
		return &e.Notification.Message.Header
	}
	return nil
}

func (s *acceptedHandshake) apply(in protocol.Input) { s.run(s.prepare(in)) }
