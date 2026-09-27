// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
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
type Client struct {
	Dict                        *dict.Parser  // Dictionary parser (uses dict.Default if unset)
	Handler                     *StateMachine // Message handler
	MaxRetransmits              uint          // Maximum CER handshake retransmissions before aborting
	RetransmitInterval          time.Duration // Interval between CER handshake retransmissions (default 1s)
	EnableWatchdog              bool          // Enable automatic DWR
	WatchdogInterval            time.Duration // RFC 3539 §3.4.1 Twinit; default 30s, minimum 6s, with ±2s jitter
	WatchdogStream              uint          // Stream to send DWR on (for multistreaming protocols), default is 0
	SupportedVendorID           []*diam.AVP   // Supported vendor ID
	AcctApplicationID           []*diam.AVP   // Acct applications
	AuthApplicationID           []*diam.AVP   // Auth applications
	VendorSpecificApplicationID []*diam.AVP   // Vendor specific applications
	InbandSecurityID            uint32        // Inband-Security-Id for CER: 0=NO_INBAND_SECURITY (default), 1=TLS (RFC 6733 §5.3.1)
	TLSConfig                   *tls.Config   // Optional TLS config used by DialTLS methods.

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

	watchdogEventMu sync.Mutex
	defaultsOnce    sync.Once
	watchdogTiming  *watchdogTiming // unexported test override for short timers
}

type watchdogTiming struct {
	floor  time.Duration
	jitter time.Duration
}

type watchdogActivity struct {
	signal  chan struct{}
	last    atomic.Int64
	dwac    chan struct{}
	ceac    chan error
	ceaOnce sync.Once
}

func newWatchdogActivity() *watchdogActivity {
	return &watchdogActivity{signal: make(chan struct{}, 1), dwac: make(chan struct{}, 1), ceac: make(chan error)}
}

type activityHandler struct {
	*StateMachine
	activity *watchdogActivity
	cea      diam.Handler
	dwa      diam.Handler
}

func (h activityHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	// RFC 3539 §3.4.1 [2]: any received AAA message resets Tw.
	h.activity.last.Store(time.Now().UnixNano())
	select {
	case h.activity.signal <- struct{}{}:
	default:
	}
	// RFC 6733 §5.3: CEA completes the CER exchange on this connection.
	// Do not publish its result through the shared state-machine mux.
	if m.Header.ApplicationID == 0 && m.Header.CommandCode == diam.CapabilitiesExchange &&
		m.Header.CommandFlags&diam.RequestFlag == 0 {
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
	return cli.DialExt("tcp", addr, 0, nil)
}

// DialNetwork calls the network address set as ip:port, performs a handshake and optionally
// start a watchdog goroutine in background.
func (cli *Client) DialNetwork(network, addr string) (diam.Conn, error) {
	return cli.DialExt(network, addr, 0, nil)
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
	return cli.DialTLSExt(network, addr, certFile, keyFile, 0, nil)
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

// NewConn is like Dial, but using an already open net.Conn.
func (cli *Client) NewConn(rw net.Conn, addr string) (diam.Conn, error) {
	return cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		return cli.server("", addr, nil, activity).NewConn(rw)
	})
}

// server builds the diam.Server template used to open outgoing connections,
// carrying the client's dictionary, handler and I/O timeouts.
func (cli *Client) server(network, addr string, laddr net.Addr, activity *watchdogActivity) *diam.Server {
	var handler diam.Handler = cli.Handler
	if activity != nil {
		h := activityHandler{StateMachine: cli.Handler, activity: activity,
			cea: handleCEA(cli.Handler, activity.ceac)}
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
	}
}

type dialFunc func(*watchdogActivity) (diam.Conn, error)

func (cli *Client) dial(f dialFunc) (diam.Conn, error) {
	if err := cli.validate(); err != nil {
		return nil, err
	}
	activity := newWatchdogActivity()
	c, err := f(activity)
	if err != nil {
		return c, err
	}
	c, err = cli.handshake(c, activity)
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
	// Make sure the applications supplied to Client are supported locally
	for _, submittedAcctApp := range cli.AcctApplicationID {
		acctAppID := uint32(submittedAcctApp.Data.(datatype.Unsigned32))
		isSupported := false
		for _, localApp := range cli.Handler.supportedApps {
			if localApp.AppType == "acct" && localApp.ID == acctAppID {
				isSupported = true
				break
			}
		}
		if !isSupported {
			err := fmt.Errorf("client attempts to advertise unsupported application - type: acct, id: %d", acctAppID)
			return err
		}

	}
	for _, submittedAuthApp := range cli.AuthApplicationID {
		authAppID := uint32(submittedAuthApp.Data.(datatype.Unsigned32))
		isSupported := false
		for _, localApp := range cli.Handler.supportedApps {
			if localApp.AppType == "auth" && localApp.ID == authAppID {
				isSupported = true
				break
			}
		}
		if !isSupported {
			err := fmt.Errorf("client attempts to advertise unsupported application - type: auth, id: %d", authAppID)
			return err
		}

	}
	return nil
}

func (cli *Client) handshake(c diam.Conn, activity *watchdogActivity) (diam.Conn, error) {
	var (
		hostAddresses []datatype.Address
		err           error
	)
	if len(cli.Handler.cfg.HostIPAddresses) > 0 {
		hostAddresses = cli.Handler.cfg.HostIPAddresses
	} else {
		hostAddresses, err = getLocalAddresses(c)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("diameter handshake failure: %v", err)
		}
	}

	m, err := cli.makeCER(hostAddresses)
	if err != nil {
		c.Close()
		return nil, err
	}
	// Ignore CER, but not DWR.
	cerClientHandler := func(c diam.Conn, m *diam.Message) {}
	// See sm.go for Base Diam Idx declarations
	cli.Handler.mux.HandleIdx(baseCERIdx, diam.HandlerFunc(cerClientHandler))
	cli.Handler.mux.HandleFunc("CER", cerClientHandler)
	// CEA and DWA are dispatched by the per-connection activityHandler.
	errc := activity.ceac
	for i := 0; i < (int(cli.MaxRetransmits) + 1); i++ {
		_, err := m.WriteTo(c)
		if err != nil {
			c.Close()
			return nil, err
		}
		select {
		case err, ok := <-errc: // Wait for CEA.
			if ok && err != nil {
				close(errc)
				c.Close()
				return nil, err
			}
			if cli.EnableWatchdog {
				go cli.watchdog(c, activity.dwac, activity)
			}
			return c, nil
		case <-time.After(cli.RetransmitInterval):
		}
	}
	c.Close()
	return nil, ErrHandshakeTimeout
}

func (cli *Client) makeCER(hostIPAddresses []datatype.Address) (*diam.Message, error) {
	cfg := baseSettings(cli.Handler.cfg)
	cfg.HostIPAddresses = hostIPAddresses
	cfg.SupportedVendorID = cli.SupportedVendorID
	cfg.AcctApplicationID = cli.AcctApplicationID
	cfg.AuthApplicationID = cli.AuthApplicationID
	cfg.VendorSpecificApplicationID = cli.VendorSpecificApplicationID
	cfg.InbandSecurityID = cli.InbandSecurityID
	return base.BuildCER(cli.Dict, cfg)
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
	disconnect := c.(diam.CloseNotifier).CloseNotify()
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
		cli.Handler.Error(&diam.ErrorReport{Conn: c, Error: err})
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
		cli.Handler.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
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
	i := len(hosts) - 1
	for ; i >= 0 && hosts[i] != ':'; i-- {
		if hosts[i] < '0' || hosts[i] > '9' {
			return "", fmt.Errorf("found non numerical character in port at position %d", i+1)
		}
	}
	return hosts[:i], nil
}

func getLocalAddresses(c diam.Conn) ([]datatype.Address, error) {
	var ips []net.IP
	switch addr := c.LocalAddr().(type) {
	case *sctp.Addr:
		if addr != nil {
			for _, ip := range addr.IPs {
				ips = append(ips, net.IP(ip.AsSlice()))
			}
		}
	case *net.TCPAddr:
		if addr != nil {
			ips = append(ips, addr.IP)
		}
	case nil:
		return nil, nil
	default:
		addrStr := addr.String()
		if addrStr != "" {
			hosts, err := getHostsWithoutPort(addrStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse local ip %s [%q]: %w", addrStr, addr, err)
			}
			for _, host := range strings.Split(hosts, "/") {
				host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
				if zone := strings.LastIndex(host, "%"); zone >= 0 {
					host = host[:zone]
				}
				ips = append(ips, net.ParseIP(host))
			}
		}
	}
	// RFC 6733 §5.3.5 requires the host's addresses in Host-IP-Address.
	// Preserve the existing loopback preference when other addresses exist.
	addresses := make([]datatype.Address, 0, len(ips))
	var loopback net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.IsLoopback() {
			loopback = ip
		} else {
			addresses = append(addresses, datatype.Address(ip))
		}
	}
	if len(addresses) == 0 && loopback != nil {
		addresses = append(addresses, datatype.Address(loopback))
	}
	return addresses, nil
}
