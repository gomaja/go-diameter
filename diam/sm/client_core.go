package sm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// watchdogActivity is the transport setup rendezvous. Protocol state belongs
// exclusively to the per-connection core, including when the reader starts
// before NewConn returns (RFC 6733 §§5.3,5.6).
type watchdogActivity struct {
	mu           sync.Mutex
	core         *acceptedHandshake
	ready        chan struct{}
	once         sync.Once
	capabilities base.Settings
	advertised   []uint32
}

func newWatchdogActivity() *watchdogActivity { return &watchdogActivity{ready: make(chan struct{})} }
func (a *watchdogActivity) state() *acceptedHandshake {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.core
}
func (a *watchdogActivity) install(s *acceptedHandshake) { a.mu.Lock(); a.core = s; a.mu.Unlock() }
func (a *watchdogActivity) release()                     { a.once.Do(func() { close(a.ready) }) }

type activityHandler struct {
	*StateMachine
	activity *watchdogActivity
}

func (h activityHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	<-h.activity.ready
	if h.activity.state() != nil {
		h.StateMachine.ServeDIAM(c, m)
	}
}
func (h activityHandler) HandleMessageError(c diam.Conn, m *diam.Message, err *diam.MessageError) error {
	<-h.activity.ready
	if h.activity.state() == nil {
		return nil
	}
	return h.StateMachine.HandleMessageError(c, m, err)
}

func (cli *Client) newCore(c diam.Conn, local base.Settings) (*acceptedHandshake, acceptedBatch, error) {
	s := &acceptedHandshake{sm: cli.Handler, conn: c, client: cli,
		id:     protocol.Connection{Instance: acceptedInstance.Add(1), Generation: connectionGeneration(c)},
		writes: make(map[uint64]*diam.RequestWrite), handshake: make(chan error, 1), handshakeDone: make(chan struct{})}
	if cli.EnableWatchdog {
		_, jitter := cli.watchdogParameters()
		s.policy = &watchdogPolicy{twinit: cli.WatchdogInterval, jitter: jitter, stream: cli.WatchdogStream,
			onEvent: func(c diam.Conn, e WatchdogEvent) { cli.emitWatchdog(c, e) }}
	}
	interval := max(cli.WatchdogInterval, watchdog.MinimumTw)
	// A TLS transport completes its handshake before writing any CER bytes.
	// The reader publishes Conn.TLS independently, so classify the transport.
	_, secured := c.Connection().(*tls.Conn)
	closingTimeout := cli.Handler.receiverCloseTimeout()
	if _, ok := diam.ConnAs[diam.CloseNotifier](c); !ok {
		closingTimeout = 0
	}
	core, err := protocol.New(protocol.Config{Connection: s.id, Role: protocol.Initiator,
		Local: local, Dictionary: cli.Dict, TLS: secured, Hooks: true,
		CERInterval: max(cli.RetransmitInterval, time.Nanosecond), MaxRetransmits: cli.MaxRetransmits,
		ClosingTimeout: closingTimeout, LocalDisconnectInClosing: true, SkipDWRGrammarAfterHook: true,
		KeepCERDeadlineAfterTransportLoss: true,
		Watchdog:                          cli.EnableWatchdog, WatchdogInterval: interval,
		ValidateRequests: cli.Handler.cfg.ValidateRequests, RejectUnknownMandatoryAVPs: cli.Handler.cfg.RejectUnknownMandatoryAVPs})
	if err != nil {
		return nil, acceptedBatch{}, err
	}
	s.core = core
	// Commit the initiator's pending handshake before publishing the core to
	// cancellation, receive dispatch or lifecycle observation (RFC 6733 §5.3).
	// The initial CER writer runs these effects synchronously after publication.
	start := s.prepare(protocol.Input{Kind: protocol.Start})
	// A Conn with no lifecycle signal owns its own core. The StateMachine
	// must not retain such connections in an uncollectable map (§5.6).
	if done := connectionDone(c); done != nil {
		cli.Handler.cores.Store(c, s)
		go func() {
			<-done
			s.apply(protocol.Input{Kind: protocol.TransportLost})
			cli.Handler.cores.CompareAndDelete(c, s)
		}()
	} else {
		cli.Handler.contextCores.Lock()
		ctx := c.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		c.SetContext(context.WithValue(ctx, contextCoreKey{cli.Handler}, s))
		cli.Handler.contextCores.Unlock()
	}
	return s, start, nil
}

func (s *acceptedHandshake) finishHandshake(err error) {
	s.handshakeOnce.Do(func() {
		s.handshake <- err
		close(s.handshakeDone)
	})
}
func (s *acceptedHandshake) completeHandshake(n protocol.Notification, in protocol.Input) {
	result := n.Handshake
	err := result.Err()
	var cea *base.CEA
	if err != nil {
		// Only rejected CEAs expose a public parser result. Successful peer
		// metadata is published independently by the admission effect.
		cea = result.CEA()
		_, err = fromValidatedCEA(cea, nil, err)
	}
	if err == nil {
		switch n.Outcome {
		case protocol.TimedOut:
			err = ErrHandshakeTimeout
		case protocol.Completed:
		case protocol.Cancelled:
			err = context.Canceled
		default:
			err = in.Err
			if err == nil && in.Error != nil {
				err = in.Error
			}
			if err == nil {
				err = errors.New("non-CEA received while waiting for CEA")
			}
		}
	} else if cea == nil && in.Error == nil {
		var messageErr *diam.MessageError
		if errors.As(err, &messageErr) {
			err = fmt.Errorf("invalid CEA: %w", err)
		}
	}
	s.finishHandshake(err)
}
