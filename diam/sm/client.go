// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-sctp"
)

var (
	// ErrMissingStateMachine is returned by Dial or DialTLS when
	// the Client does not have a valid StateMachine set.
	ErrMissingStateMachine = errors.New("client state machine is nil")

	// ErrHandshakeTimeout is returned by Dial or DialTLS when the
	// client does not receive a handshake answer from the server.
	//
	// If the client is configured to retransmit messages, the
	// handshake timeout only occurs after all retransmits are
	// attempted and none has an aswer.
	ErrHandshakeTimeout = errors.New("handshake timeout (no response)")
)

// A Client is a diameter client that automatically performs a handshake
// with the server after the connection is established.
//
// It sends a Capabilities-Exchange-Request with the AVPs defined in it,
// and expects a Capabilities-Exchange-Answer with a success (2001) result
// code. If enabled, the client will send Device-Watchdog-Request messages
// in background until the connection is terminated.
//
// By default, CER retransmission and watchdog are disabled. CER retransmission
// is enabled by setting MaxRetransmits to a number greater than zero, and
// watchdog is enabled by setting EnableWatchdog to true. Watchdog DWRs are
// never retransmitted (RFC 3539 §3.4.1).
//
// RFC 3539 Appendix A's INITIAL and REOPEN states belong to a managed
// connection lifecycle. Client starts its watchdog after the handshake and
// does not reconnect connections it has closed.
//
// A custom message handler for Device-Watchdog-Answer (DWA) can be registered.
// With watchdog enabled, Client handles DWA on its connections first.
// For custom connections whose LocalAddr is neither a TCP nor SCTP address,
// LocalAddr.String must contain literal IP addresses. An unparseable host
// causes the capability exchange handshake to fail.
type Client struct {
	Dict               *dict.Parser  // Dictionary parser (uses dict.Default if unset)
	Handler            *StateMachine // Message handler
	MaxRetransmits     uint          // Maximum CER handshake retransmissions before aborting
	RetransmitInterval time.Duration // Interval between CER handshake retransmissions (default 1s)
	EnableWatchdog     bool          // Enable automatic DWR
	WatchdogInterval   time.Duration // RFC 3539 §3.4.1 Twinit; default 30s, minimum 6s, with ±2s jitter
	WatchdogStream     uint          // Stream to send DWR on (for multistreaming protocols), default is 0
	// SupportedVendorID overrides Settings.SupportedVendorID when non-nil.
	// Configured AVPs are sent exactly as supplied, including order and repetitions.
	SupportedVendorID []*diam.AVP
	// If any application slice is non-nil, these three slices replace the
	// Settings application slices for CER. Values are sent exactly as supplied;
	// a non-nil empty slice is explicit. Dial rejects malformed VSAI groups
	// before opening the connection (RFC 6733 §6.11, Verified Erratum 4808).
	AcctApplicationID           []*diam.AVP
	AuthApplicationID           []*diam.AVP
	VendorSpecificApplicationID []*diam.AVP
	InbandSecurityID            uint32      // Inband-Security-Id for CER: 0=omitted default, 1=TLS on an already secured connection (RFC 6733 §§5.3.1, 6.10)
	TLSConfig                   *tls.Config // Optional TLS config used by DialTLS methods.

	// ReadTimeout is the maximum duration for reading a message from the
	// peer. Zero means no read deadline.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing a message to the
	// peer. Zero means no write deadline.
	//
	// Writes are serialized on a per-connection mutex, so an unbounded
	// write to a peer that has stopped draining its socket blocks every
	// other sender behind it — including the watchdog's DWR, which would
	// otherwise never reach its own timeout. Setting this bounds that.
	//
	WriteTimeout time.Duration

	// OnWatchdogEvent, when non-nil, observes client-side watchdog outcomes.
	// The callback may be called by the watchdog and message-handler goroutines,
	// so it must be concurrency-safe and return promptly. Events carry no
	// Diameter message or AVP payload.
	OnWatchdogEvent func(WatchdogEvent)
	// OnWatchdogConnEvent observes the same events with the connection that
	// produced each event. Like OnWatchdogEvent, it must be concurrency-safe
	// and return promptly. The existing callback runs first when both are set.
	OnWatchdogConnEvent func(diam.Conn, WatchdogEvent)

	// Logger receives the records of the connections the client opens, as
	// diam.Server.Logger does for a server. Nil uses slog.Default.
	Logger *slog.Logger

	watchdogEventMu sync.Mutex
	defaultsOnce    sync.Once
	watchdogTiming  *watchdogTiming // unexported test override for short timers
}

type watchdogTiming struct {
	floor  time.Duration
	jitter time.Duration
}

type watchdogActivity struct {
	signal         chan struct{}
	last           atomic.Int64
	dwac           chan struct{}
	ceac           chan error
	ceaOnce        sync.Once
	ceaReceived    atomic.Bool
	ceaValidated   chan struct{}
	handshakePhase atomic.Uint32 // 0 pending, 1 validated, 2 timed out
	advertised     []uint32
	capabilities   base.Settings
}

func newWatchdogActivity() *watchdogActivity {
	return &watchdogActivity{signal: make(chan struct{}, 1), dwac: make(chan struct{}, 1), ceac: make(chan error, 1), ceaValidated: make(chan struct{})}
}

type activityHandler struct {
	*StateMachine
	activity *watchdogActivity
	cea      diam.Handler
	dwa      diam.Handler
}

func (h activityHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	release := m.BeginDispatch()
	defer release()
	// RFC 6733 §5.6: Wait-I-CEA / I-Rcv-Non-CEA -> Error -> Closed.
	isCEA := m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag == 0
	if !h.activity.ceaReceived.Load() && !isCEA {
		h.rejectHandshake(c, errors.New("non-CEA received while waiting for CEA"))
		return
	}
	// RFC 6733 §§2.5 and 5.5.2: invalid base headers cannot confirm liveness.
	// StateMachine reports/discards invalid answers and answers invalid requests.
	if base.ValidateHeader(m) != nil {
		h.StateMachine.ServeDIAM(c, m)
		return
	}
	// RFC 3539 §3.4.1 [2]: any received AAA message resets Tw.
	h.activity.last.Store(time.Now().UnixNano())
	select {
	case h.activity.signal <- struct{}{}:
	default:
	}
	// RFC 6733 §5.3: CEA completes the CER exchange on this connection.
	// Do not publish its result through the shared state-machine mux.
	if isCEA {
		h.activity.ceaOnce.Do(func() { h.cea.ServeDIAM(c, m) })
		return
	}
	// RFC 6733 §5.5.2: DWA belongs to the connection that received it.
	// Keep its handler with that connection instead of replacing a handler on
	// the shared state-machine mux on every Dial.
	if h.dwa != nil && m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.DeviceWatchdog &&
		m.Header.CommandFlags&diam.RequestFlag == 0 {
		h.dwa.ServeDIAM(c, m)
		return
	}
	h.StateMachine.ServeDIAM(c, m)
}

// HandleMessageError also enforces Wait-I-CEA for malformed input, which
// the transport does not dispatch through ServeDIAM (RFC 6733 §5.6).
func (h activityHandler) HandleMessageError(c diam.Conn, m *diam.Message, err *diam.MessageError) error {
	release := m.BeginDispatch()
	defer release()
	if !h.activity.ceaReceived.Load() {
		h.rejectHandshake(c, err)
		return nil
	}
	return h.StateMachine.HandleMessageError(c, m, err)
}

func (h activityHandler) rejectHandshake(c diam.Conn, err error) {
	logMessage(c, nil, slog.LevelWarn, "sm: Wait-I-CEA rejected message; closing connection", err)
	h.activity.ceaOnce.Do(func() { h.activity.ceac <- err })
	c.Close()
}

// WatchdogEvent identifies a bounded client-side watchdog outcome from the
// RFC 6733 Sections 5.5.1-5.5.3 and RFC 3539 Section 3.4.1 exchange.
type WatchdogEvent string

const (
	WatchdogRequestSent    WatchdogEvent = "request_sent"
	WatchdogAnswerReceived WatchdogEvent = "answer_received"
	WatchdogInvalidAnswer  WatchdogEvent = "invalid_answer"
	WatchdogWriteFailed    WatchdogEvent = "write_failed"
	WatchdogSuspect        WatchdogEvent = "suspect"   // RFC 3539 Appendix A: outstanding DWR at Tw expiration
	WatchdogRecovered      WatchdogEvent = "recovered" // RFC 3539 Appendix A: traffic received in SUSPECT
	WatchdogTimedOut       WatchdogEvent = "timeout"   // RFC 3539 Appendix A: DOWN after another Tw expiration
)

func (cli *Client) observeWatchdog(c diam.Conn, event WatchdogEvent) {
	cli.watchdogEventMu.Lock()
	defer cli.watchdogEventMu.Unlock()
	cli.emitWatchdog(c, event)
}

func (cli *Client) emitWatchdog(c diam.Conn, event WatchdogEvent) {
	if cli.OnWatchdogEvent != nil {
		cli.OnWatchdogEvent(event)
	}
	if cli.OnWatchdogConnEvent != nil {
		cli.OnWatchdogConnEvent(c, event)
	}
}

// Dial calls the address set as ip:port, performs a handshake and optionally
// start a watchdog goroutine in background.
func (cli *Client) Dial(addr string) (diam.Conn, error) {
	return cli.DialContext(context.Background(), "tcp", addr, nil)
}

// DialNetwork calls the network address set as ip:port, performs a handshake and optionally
// start a watchdog goroutine in background.
func (cli *Client) DialNetwork(network, addr string) (diam.Conn, error) {
	return cli.DialContext(context.Background(), network, addr, nil)
}

// DialNetworkBind calls the network address set as ip:port, performs a handshake and optionally
// start a watchdog goroutine in background.
func (cli *Client) DialNetworkBind(network, laddr, raddr string) (diam.Conn, error) {
	return cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server(network, raddr, nil, activity).DialBind(laddr, 0)
	})
}

// DialTimeout is like Dial, but with timeout
func (cli *Client) DialTimeout(addr string, timeout time.Duration) (diam.Conn, error) {
	return cli.DialExt("tcp", addr, timeout, nil)
}

// DialTLS is like Dial, but using TLS.
func (cli *Client) DialTLS(addr, certFile, keyFile string) (diam.Conn, error) {
	return cli.DialTLSExt("tcp", addr, certFile, keyFile, 0, nil)
}

// DialTLSTimeout is like DialTimeout, but using TLS.
func (cli *Client) DialTLSTimeout(addr, certFile, keyFile string, timeout time.Duration) (diam.Conn, error) {
	return cli.DialTLSExt("tcp", addr, certFile, keyFile, timeout, nil)
}

// DialNetworkTLS calls the network address set as ip:port, performs a handshake and optionally
// start a watchdog goroutine in background.
func (cli *Client) DialNetworkTLS(network, addr, certFile, keyFile string, laddr net.Addr) (diam.Conn, error) {
	return cli.DialTLSExt(network, addr, certFile, keyFile, 0, laddr)
}

// DialExt - Optionally binds client to laddr, calls the network address set as ip:port,
// performs a handshake and optionally start a watchdog goroutine in background.
func (cli *Client) DialExt(network, addr string, timeout time.Duration, laddr net.Addr) (diam.Conn, error) {
	return cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server(network, addr, laddr, activity).Dial(timeout)
	})
}

// DialTLSExt - Optionally binds client to laddr, calls the network address set as ip:port, performs a
// handshake and optionally start a watchdog goroutine in background.
func (cli *Client) DialTLSExt(
	network, addr, certFile, keyFile string, timeout time.Duration, laddr net.Addr) (diam.Conn, error) {

	return cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server(network, addr, laddr, activity).DialTLS(certFile, keyFile, timeout)
	})
}

// DialContext connects and completes CER/CEA capability exchange (RFC 6733
// §5.3). The context bounds transport establishment and all CER retransmissions.
// Cancellation closes an unfinished connection. After a successful return,
// cancelling ctx has no effect on the connection or its watchdog. If CEA
// acceptance wins the race with cancellation, OnHandshake may run even when
// DialContext returns ctx.Err(); cancellation cannot stop application callbacks.
func (cli *Client) DialContext(ctx context.Context, network, addr string, laddr net.Addr) (diam.Conn, error) {
	return cli.dialContext(ctx, func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server(network, addr, laddr, activity).DialContext(ctx)
	})
}

// DialTLSContext is DialContext with TLS. The context also bounds the TLS
// handshake. Cancellation after a successful return has no effect.
func (cli *Client) DialTLSContext(ctx context.Context, network, addr, certFile, keyFile string, laddr net.Addr) (diam.Conn, error) {
	return cli.dialContext(ctx, func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server(network, addr, laddr, activity).DialTLSContext(ctx, certFile, keyFile)
	})
}

// NewConn is like Dial, but using an already open net.Conn.
func (cli *Client) NewConn(rw net.Conn, addr string) (diam.Conn, error) {
	return cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server("", addr, nil, activity).NewConn(rw)
	})
}

// server builds the diam.Server template used to open outgoing connections,
// carrying the client's dictionary, handler, I/O timeouts and logger.
func (cli *Client) server(network, addr string, laddr net.Addr, activity *watchdogActivity) *diam.Server {
	var handler diam.Handler = cli.Handler
	if activity != nil {
		h := activityHandler{StateMachine: cli.Handler, activity: activity,
			cea: handleCEA(cli.Handler, activity)}
		if cli.EnableWatchdog {
			h.dwa = handshakeOK(handleDWA(cli.Handler, activity.dwac, cli.observeWatchdog))
		}
		handler = h
	}
	return &diam.Server{
		Network:      network,
		Addr:         addr,
		Handler:      handler,
		Dict:         cli.Dict,
		LocalAddr:    laddr,
		TLSConfig:    cli.TLSConfig,
		ReadTimeout:  cli.ReadTimeout,
		WriteTimeout: cli.WriteTimeout,
		Logger:       cli.Logger,
	}
}

type dialFunc func(*watchdogActivity) (diam.Conn, error)

func (cli *Client) dial(f dialFunc) (diam.Conn, error) {
	return cli.dialContext(context.Background(), f)
}

func (cli *Client) dialContext(ctx context.Context, f dialFunc) (diam.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cli.validate(); err != nil {
		return nil, err
	}
	activity := newWatchdogActivity()
	activity.capabilities = cli.capabilitySettings(nil)
	activity.advertised = base.AdvertisedApplicationIDs(activity.capabilities)
	c, err := f(activity)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return c, err
	}
	c, err = cli.handshakeContext(ctx, c, activity)
	return c, err
}

func (cli *Client) validate() error {
	if cli.Handler == nil {
		return ErrMissingStateMachine
	}
	// Concurrent Dials share Client configuration. Publish the defaults once
	// before any connection starts reading them.
	cli.defaultsOnce.Do(func() {
		if cli.Dict == nil {
			cli.Dict = dict.Default
		}
		if cli.RetransmitInterval == 0 {
			cli.RetransmitInterval = time.Second
		}
		if cli.WatchdogInterval == 0 {
			// RFC 3539 §3.4.1 [1] default Twinit.
			cli.WatchdogInterval = 30 * time.Second
		}
	})
	if cli.EnableWatchdog {
		floor, _ := cli.watchdogParameters()
		if cli.WatchdogInterval < floor {
			return fmt.Errorf("watchdog interval %s is below RFC 3539 §3.4.1 minimum %s", cli.WatchdogInterval, floor)
		}
	}
	if err := base.ValidateCapabilities(cli.capabilitySettings(nil)); err != nil {
		return fmt.Errorf("client: invalid capabilities configuration: %w", err)
	}
	return nil
}

func (cli *Client) handshake(c diam.Conn, activity *watchdogActivity) (diam.Conn, error) {
	return cli.handshakeContext(context.Background(), c, activity)
}

func (cli *Client) handshakeContext(ctx context.Context, c diam.Conn, activity *watchdogActivity) (conn diam.Conn, err error) {
	// Closing the transport also interrupts a blocked CER write. Join the callback
	// before returning so cancellation cannot close a successfully returned Conn.
	closed := make(chan struct{})
	cancelDial := func() {
		// Arbitrate cancellation against CEA acceptance before touching transport
		// state, just as the CER timeout does (RFC 6733 §5.3).
		activity.handshakePhase.CompareAndSwap(0, 2)
		abortDial(c)
	}
	closeConn := func() {
		if ctx.Err() != nil {
			cancelDial()
		} else {
			c.Close()
		}
	}
	stop := context.AfterFunc(ctx, func() { cancelDial(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
		if ctx.Err() != nil {
			cancelDial()
			conn, err = nil, ctx.Err()
		}
		if err == nil && cli.EnableWatchdog {
			go cli.watchdog(c, activity.dwac, activity)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// RFC 6733 §§5.3 and 6.10: this client cannot upgrade plaintext
	// to in-band TLS after CER/CEA, so it must not offer TLS on that path.
	if cli.InbandSecurityID == 1 {
		tlsConn, ok := c.Connection().(*tls.Conn)
		if !ok {
			closeConn()
			return nil, fmt.Errorf("Inband-Security-Id=1 requires an already established TLS connection")
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			closeConn()
			return nil, fmt.Errorf("TLS handshake before CER: %w", err)
		}
	}
	var hostAddresses []datatype.Address
	if len(cli.Handler.cfg.HostIPAddresses) > 0 {
		hostAddresses = cli.Handler.cfg.HostIPAddresses
	} else {
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			closeConn()
			return nil, fmt.Errorf("diameter handshake failure: %w", err)
		}
	}

	cfg := activity.capabilities
	cfg.HostIPAddresses = hostAddresses
	m, err := base.BuildCER(cli.Dict, cfg)
	if err != nil {
		closeConn()
		return nil, err
	}
	// CEA validation ends the protocol timeout. OnHandshake completion is a
	// separate event: an application callback may take longer than the entire
	// retransmit budget, and Dial must still wait for it (RFC 6733 §5.3).
	finish := func(err error) (diam.Conn, error) {
		if err != nil {
			closeConn()
			return nil, err
		}
		return c, nil
	}
	waitCEA := func() (diam.Conn, error) {
		select {
		case <-ctx.Done():
			return finish(ctx.Err())
		case err := <-activity.ceac:
			return finish(err)
		}
	}
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for i := uint(0); ; i++ {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		if activity.handshakePhase.Load() == 1 {
			return waitCEA()
		}
		if _, err := m.WriteTo(c); err != nil {
			closeConn()
			return nil, err
		}
		timer.Reset(cli.RetransmitInterval)
		select {
		case <-ctx.Done():
			return finish(ctx.Err())
		case err := <-activity.ceac:
			return finish(err)
		case <-activity.ceaValidated:
			return waitCEA()
		case <-timer.C:
		}
		if i == cli.MaxRetransmits {
			break
		}
	}
	// Arbitrate a CEA arriving at the deadline. Once validation wins, a slow
	// callback cannot be mistaken for an unanswered CER.
	if !activity.handshakePhase.CompareAndSwap(0, 2) {
		return waitCEA()
	}

	logMessage(c, nil, slog.LevelWarn, "sm: CEA timeout; closing connection", ErrHandshakeTimeout)
	closeConn()
	return nil, ErrHandshakeTimeout
}

// abortDial terminates a cancelled dial without SCTP's graceful shutdown wait
// (RFC 9260 §9.1). Unwrap TLS before checking for the transport's Abort method.
// Close still publishes Diameter's Closed state after the transport is aborted.
func abortDial(c diam.Conn) {
	for rw := c.Connection(); rw != nil; {
		if conn, ok := rw.(interface{ Abort() error }); ok {
			_ = conn.Abort()
			break
		}
		conn, ok := rw.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		rw = conn.NetConn()
	}
	c.Close()
}

func (cli *Client) makeCER(hostIPAddresses []datatype.Address) (*diam.Message, error) {
	cfg := cli.capabilitySettings(hostIPAddresses)
	dictionary := cli.Dict
	if dictionary == nil {
		dictionary = dict.Default
	}
	return base.BuildCER(dictionary, cfg)
}

func (cli *Client) capabilitySettings(hostIPAddresses []datatype.Address) base.Settings {
	cfg := baseSettings(cli.Handler.cfg)
	cfg.HostIPAddresses = hostIPAddresses
	if cli.SupportedVendorID != nil {
		cfg.SupportedVendorID = cli.SupportedVendorID
	}
	dictionary := cli.Dict
	if dictionary == nil {
		dictionary = dict.Default
	}
	// Dictionary metadata supplies derived capabilities and AVP vendors.
	for _, app := range PrepareSupportedApps(dictionary) {
		cfg.Applications = append(cfg.Applications, base.LocalApplication{
			ID: app.ID, AppType: app.AppType, Vendor: app.Vendor, SupportedVendors: app.SupportedVendors,
		})
	}
	if cli.AcctApplicationID != nil || cli.AuthApplicationID != nil || cli.VendorSpecificApplicationID != nil {
		cfg.AcctApplicationID = cli.AcctApplicationID
		cfg.AuthApplicationID = cli.AuthApplicationID
		cfg.VendorSpecificApplicationID = cli.VendorSpecificApplicationID
	}
	cfg.InbandSecurityID = cli.InbandSecurityID
	return cfg
}

func (cli *Client) watchdogParameters() (floor, jitter time.Duration) {
	if cli.watchdogTiming != nil {
		return cli.watchdogTiming.floor, cli.watchdogTiming.jitter
	}
	return 6 * time.Second, 2 * time.Second
}

func (cli *Client) nextWatchdogInterval() time.Duration {
	_, jitter := cli.watchdogParameters()
	if jitter == 0 {
		return cli.WatchdogInterval
	}
	// RFC 3539 §3.4.1 [1]: Tw = Twinit - 2s + 4s * random().
	return cli.WatchdogInterval - jitter + time.Duration(rand.Int63n(int64(2*jitter)+1))
}

func (cli *Client) watchdog(c diam.Conn, dwac chan struct{}, activity *watchdogActivity) {
	notifier, ok := diam.ConnAs[diam.CloseNotifier](c)
	if !ok {
		logMessage(c, nil, slog.LevelWarn, "sm: watchdog disabled: connection does not expose CloseNotifier", nil)
		return
	}
	disconnect := notifier.CloseNotify()
	var osid = uint32(cli.Handler.cfg.OriginStateID)
	// RFC 3539 §3.4.1 and Appendix A: established peers start in OKAY.
	// Pending remains set after non-DWA traffic until the answer arrives.
	pending := false
	suspect := false
	for {
		armedAt := time.Now()
		timer := time.NewTimer(cli.nextWatchdogInterval())
		select {
		case <-disconnect:
			timer.Stop()
			return
		case <-activity.signal:
			timer.Stop()
			if suspect {
				suspect = false
				cli.observeWatchdog(c, WatchdogRecovered)
			}
		case <-dwac:
			timer.Stop()
			pending = false
			if suspect {
				suspect = false
				cli.observeWatchdog(c, WatchdogRecovered)
			}
		case <-timer.C:
			// Prefer traffic delivered at the timer boundary to a false
			// expiration, including an answer already queued by its handler.
			if activity.last.Load() > armedAt.UnixNano() {
				if suspect {
					suspect = false
					cli.observeWatchdog(c, WatchdogRecovered)
				}
				continue
			}
			select {
			case <-dwac:
				pending = false
				if suspect {
					suspect = false
					cli.observeWatchdog(c, WatchdogRecovered)
				}
				continue
			default:
			}
			if suspect {
				// RFC 3539 Appendix A: a second Tw expiry in SUSPECT
				// transitions to DOWN and closes this connection.
				cli.observeWatchdog(c, WatchdogTimedOut)
				logMessage(c, nil, slog.LevelWarn, "sm: watchdog timeout; closing connection", nil)
				c.Close()
				return
			}
			if pending {
				// RFC 3539 Appendix A: failover belongs to the caller's
				// supervisor; Client reports SUSPECT but has no peer queue.
				suspect = true
				cli.observeWatchdog(c, WatchdogSuspect)
				continue
			}
			if !cli.dwr(c, osid) {
				return
			}
			pending = true
		}
	}
}

func (cli *Client) dwr(c diam.Conn, osid uint32) bool {
	m, err := cli.makeDWR(osid)
	if err != nil {
		logMessage(c, nil, slog.LevelError, "sm: watchdog request failed; closing connection", err)
		c.Close()
		return false
	}
	// Serialize successful request publication with DWA publication. A peer
	// can answer before WriteToStream returns, but observers still receive
	// the causal request event first.
	cli.watchdogEventMu.Lock()
	_, err = m.WriteToStream(c, cli.WatchdogStream)
	if err != nil {
		cli.emitWatchdog(c, WatchdogWriteFailed)
		cli.watchdogEventMu.Unlock()
		logMessage(c, m, slog.LevelError, "sm: watchdog request failed; closing connection", err)
		c.Close()
		return false
	}
	cli.emitWatchdog(c, WatchdogRequestSent)
	cli.watchdogEventMu.Unlock()
	return true
}

func (cli *Client) makeDWR(osid uint32) (*diam.Message, error) {
	return base.BuildDWR(cli.Dict, baseSettings(cli.Handler.cfg), osid)
}

func getHostsWithoutPort(hosts string) (string, error) {
	i := strings.LastIndexByte(hosts, ':')
	if i < 0 {
		return "", errors.New("missing local address port")
	}
	for j := i + 1; j < len(hosts); j++ {
		if hosts[j] < '0' || hosts[j] > '9' {
			return "", fmt.Errorf("found non numerical character in port at position %d", j+1)
		}
	}
	return hosts[:i], nil
}

// getLocalAddresses resolves the local endpoint advertised in CER or CEA.
// Custom non-TCP/SCTP LocalAddr values must contain literal IP hosts; names
// cannot be encoded as RFC 6733 §4.3.1 Address values and fail the handshake.
func getLocalAddresses(c diam.Conn) ([]datatype.Address, error) {
	var ips []netip.Addr
	switch addr := c.LocalAddr().(type) {
	case *sctp.Addr:
		if addr != nil {
			ips = append(ips, addr.IPs...)
		}
	case *net.TCPAddr:
		if addr != nil {
			ips = append(ips, addr.AddrPort().Addr())
		}
	case nil:
		return nil, nil
	default:
		addrStr := addr.String()
		if addrStr == "" {
			return nil, errors.New("empty local address")
		}
		hosts, err := getHostsWithoutPort(addrStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local ip %s [%q]: %w", addrStr, addr, err)
		}
		for _, host := range strings.Split(hosts, "/") {
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
			if zone := strings.LastIndex(host, "%"); zone >= 0 {
				host = host[:zone]
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("failed to parse local IP %q: %w", host, err)
			}
			ips = append(ips, ip)
		}
	}
	// RFC 6733 §5.3.5 requires the host's addresses in Host-IP-Address.
	// Preserve the existing loopback preference when other addresses exist.
	addresses := make([]datatype.Address, 0, len(ips))
	var loopback netip.Addr
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		if ip.IsLoopback() {
			loopback = ip
		} else {
			addresses = append(addresses, datatype.AddressFromIP(ip))
		}
	}
	if len(addresses) == 0 && loopback.IsValid() {
		addresses = append(addresses, datatype.AddressFromIP(loopback))
	}
	return addresses, nil
}
