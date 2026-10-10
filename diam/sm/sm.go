// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// SupportedApp holds properties of each locally supported App
type SupportedApp struct {
	ID      uint32
	AppType string
	// Vendor identifies the application author; zero for standard/relay IDs.
	Vendor uint32
	// SupportedVendors includes every XML vendor whose AVPs are supported.
	SupportedVendors []uint32
}

// PrepareSupportedApps prepares a list of locally supported apps
func PrepareSupportedApps(d *dict.Parser) []*SupportedApp {
	locallySupportedApps := []*SupportedApp{}
	for _, app := range d.Apps() {
		if app.ID == 0 {
			continue
		}
		addApp := new(SupportedApp)
		addApp.ID = app.ID
		addApp.AppType = app.Type
		addApp.Vendor = app.ApplicationVendor()
		for _, vendor := range app.Vendor {
			addApp.SupportedVendors = append(addApp.SupportedVendors, vendor.ID)
		}
		locallySupportedApps = append(locallySupportedApps, addApp)
	}
	return locallySupportedApps
}

// Settings used to configure the state machine with AVPs to be added
// to CER on clients or CEA on servers.
// StateMachine supports Server.MaxConcurrentHandlers by ordering protocol
// admission internally. See StateMachine for the middleware contract.
type Settings struct {
	OriginHost  datatype.DiameterIdentity
	OriginRealm datatype.DiameterIdentity
	VendorID    datatype.Unsigned32
	ProductName datatype.UTF8String

	// SupportedVendorID is sent exactly as configured, including order,
	// repetitions, and the device vendor. Nil derives vendors from the
	// advertised applications; a non-nil empty slice advertises none.
	// Client.SupportedVendorID takes precedence when set (RFC 6733 §5.3.6).
	SupportedVendorID []*diam.AVP

	// These application AVPs are sent exactly as configured. If all three
	// slices are nil, applications are derived from Dict. A non-nil empty
	// slice counts as explicit configuration. A Client with any non-nil
	// application slice overrides all three Settings slices for its CER.
	// Vendor-Specific-Application-Id must have exactly one Vendor-Id and
	// exactly one Auth- or Acct-Application-Id (RFC 6733 §6.11, Verified
	// Erratum 4808); New rejects malformed groups. Application 0 is implicit
	// and must not be advertised (RFC 6733 §§2.4, 5.3).
	AuthApplicationID           []*diam.AVP
	AcctApplicationID           []*diam.AVP
	VendorSpecificApplicationID []*diam.AVP

	// OriginStateID is optional for clients and servers and is omitted if unset.
	// RFC 6733 §8.16 requires it to reflect this entity's Origin-Host.
	//
	// May be set to datatype.Unsigned32(time.Now().Unix()).
	OriginStateID datatype.Unsigned32

	// FirmwareRevision is optional, and not added if unset.
	FirmwareRevision datatype.Unsigned32

	// HostIPAddresses is optional for both clients and servers, when not set local
	// host IP address is used.
	//
	// This property may be set when the IP address of the host sending/receiving
	// the request is different from the configured allowed IPs in the other end,
	// for example when using a VPN or a gateway.
	//
	HostIPAddresses []datatype.Address

	// Dict supplies application metadata for derived advertisement and
	// validation. If nil, each connection's dictionary is used, falling back
	// to the message dictionary when needed (RFC 6733 §5.3).
	Dict *dict.Parser

	// OnHandshake runs once after a successful CER/CEA exchange (RFC 6733 §5.3):
	// on the CER handler's goroutine after writing a success CEA, or on the CEA
	// validator's goroutine before Client.Dial returns. peer is also available
	// through smpeer.FromContext(c.Context()). The message's BeginDispatch
	// barrier remains held until this callback returns: no later message is
	// admitted to state-machine handlers, in sequential or concurrent dispatch.
	// The reader may continue reading in concurrent mode. The callback must not
	// wait for later messages on this connection or call Disconnect for it.
	OnHandshake func(c diam.Conn, peer *smpeer.Metadata)

	// OnCER, if non-nil, is invoked when a CER is received, before the
	// state machine processes it. Useful for logging, metrics, or access
	// control. The default handshake logic runs after OnCER returns.
	// Calling c.Close() from the hook aborts the handshake without publishing
	// peer metadata, admitting the peer, building a CEA, or calling OnCEA or
	// OnHandshake. A connection wrapper's Close must call the wrapped Close.
	// Closing c.Connection() directly is not detected by this hook contract.
	OnCER diam.HandlerFunc

	// OnCEA, if non-nil, is invoked immediately before a CEA is sent (both
	// the success CEA and the error CEA). Useful for logging or metrics.
	OnCEA diam.HandlerFunc

	// OnDWR, if non-nil, is invoked when a DWR is received (after the
	// peer has passed the handshake) before the state machine responds
	// with DWA (RFC 6733 §5.5, RFC 3539 §3.4.1). Calling c.Close() from the
	// hook aborts processing without building a DWA or calling OnDWA. A connection
	// wrapper's Close must call the wrapped Close. Closing c.Connection() directly
	// is not detected by this hook contract.
	OnDWR diam.HandlerFunc

	// OnDWA, if non-nil, is invoked immediately before a DWA is sent in
	// response to a peer DWR. Useful for logging or metrics.
	OnDWA diam.HandlerFunc

	// RejectUnknownMandatoryAVPs enables RFC 6733 §§4.1 and 7.1.5 rejection
	// of unknown mandatory AVPs. It defaults to false: relays must forward
	// unknown AVPs, and incomplete application dictionaries may omit vendor AVPs.
	RejectUnknownMandatoryAVPs bool

	// ValidateRequests checks received requests against command and Grouped
	// AVP dictionary grammar before dispatch. It defaults to false because
	// application dictionaries may be incomplete. Answers are never checked.
	ValidateRequests bool

	// OnDPR observes a validated peer DPR and its Disconnect-Cause after the
	// DPA is sent. Callers decide whether to reconnect (RFC 6733 §5.4.3).
	OnDPR func(diam.Conn, DisconnectCause)

	// DPRCloseTimeout bounds the receiver's Closing state (RFC 6733 §5.6).
	// Zero uses 5 seconds.
	DPRCloseTimeout time.Duration

	// HandshakeTimeout bounds the CER/CEA exchange on accepted connections
	// (RFC 6733 §5.6.1). Zero uses DefaultHandshakeTimeout; a negative
	// value disables the limit. It starts after the transport handshake.
	// Dialed connections are unaffected. Server.Handler must be this
	// StateMachine or wrap it through Unwrap() diam.Handler. A wrapper
	// without Unwrap hides both the pre-CER gate and this timeout.
	HandshakeTimeout time.Duration
}

// DefaultHandshakeTimeout applies when Settings.HandshakeTimeout is zero.
// RFC 6733 §5.6.1 permits an implementation-defined pre-CER timeout.
const DefaultHandshakeTimeout = 30 * time.Second

// Validate checks settings that would make a capability exchange invalid.
// RFC 6733 §4.3.1 defines the family and payload of each Address AVP.
// Explicit application and Supported-Vendor-Id AVPs must be well formed, and
// each Vendor-Specific-Application-Id must have exactly one Vendor-Id and
// exactly one Auth- or Acct-Application-Id (RFC 6733 §6.11, Verified
// Erratum 4808). Application 0 must not be advertised (RFC 6733 §§2.4, 5.3).
// Valid explicit values are sent as configured.
func (settings *Settings) Validate() error {
	if settings == nil {
		return fmt.Errorf("nil settings")
	}
	for i, address := range settings.HostIPAddresses {
		if err := address.Valid(); err != nil {
			return fmt.Errorf("HostIPAddresses[%d]: %w", i, err)
		}
	}
	if err := base.ValidateCapabilities(baseSettings(settings)); err != nil {
		return fmt.Errorf("invalid capabilities configuration: %w", err)
	}
	return nil
}

var (
	baseCERIdx = diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: true}
	baseCEAIdx = diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: false}
	baseDWRIdx = diam.CommandIndex{AppID: 0, Code: diam.DeviceWatchdog, Request: true}
	baseDPRIdx = diam.CommandIndex{AppID: 0, Code: diam.DisconnectPeer, Request: true}
	baseDPAIdx = diam.CommandIndex{AppID: 0, Code: diam.DisconnectPeer, Request: false}
)

// StateMachine is a specialized type of diam.ServeMux that handles
// the CER/CEA handshake and DWR/DWA messages for clients or servers.
//
// Other handlers registered in the state machine are only executed
// after the peer has passed the initial CER/CEA handshake.
// With concurrent server dispatch, admission waits for earlier callbacks;
// independent application handlers can then run concurrently. Install the
// StateMachine as Server.Handler, directly or through Unwrap() diam.Handler
// wrappers, so HandlerAs discovers HandleAccept and starts the handshake
// timeout. A mux route or opaque wrapper cannot start that timer; the state
// machine still rejects non-CER traffic until peer metadata is established.
//
// Wrappers must synchronously forward ServeDIAM (or consume the message) before
// returning. HandlerAs calls the inner HandleMessageError directly through plain
// Unwrap wrappers, which need not forward optional methods. A wrapper that itself
// implements MessageErrorHandler intercepts it and must delegate synchronously
// via HandlerAs on its inner handler (or take responsibility itself). Returning
// before forwarding forfeits that message's position in admission order.
type StateMachine struct {
	cfg           *Settings
	mux           *diam.ServeMux
	dwrHandler    diam.Handler
	supportedApps []*SupportedApp
	dictionary    *dict.Parser
	disconnects   disconnectState
	accepted      sync.Map // diam.Conn -> *acceptedHandshake
}

type acceptedHandshake struct {
	mu       sync.Mutex
	complete bool
	timedOut bool
	timer    *time.Timer
}

// New creates and initializes a new StateMachine for clients or servers.
// See Settings.Dict for the advertising and validation dictionaries.
func New(settings *Settings) (*StateMachine, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	dp := settings.Dict
	if dp == nil {
		dp = dict.Default
	}
	sm := &StateMachine{
		cfg:           settings,
		mux:           diam.NewServeMux(),
		supportedApps: PrepareSupportedApps(dp),
		dictionary:    settings.Dict,
	}
	cerHandler := chainPreHook(settings.OnCER, handleCER(sm))
	sm.dwrHandler = chainPreHook(settings.OnDWR, handleDWR(sm))
	dwrHandler := diam.HandlerFunc(func(c diam.Conn, m *diam.Message) { sm.dwrHandler.ServeDIAM(c, m) })
	sm.mux.Handle("CER", cerHandler)
	sm.mux.Handle("DWR", handshakeOK(dwrHandler))
	sm.mux.Handle("DPR", handshakeOK(handleDPR(sm)))
	sm.mux.Handle("DPA", handshakeOK(handleDPA(sm)))
	sm.mux.HandleIdx(baseCERIdx, cerHandler)
	sm.mux.HandleIdx(baseDWRIdx, handshakeOK(dwrHandler))
	sm.mux.HandleIdx(baseDPRIdx, handshakeOK(handleDPR(sm)))
	sm.mux.HandleIdx(baseDPAIdx, handshakeOK(handleDPA(sm)))
	return sm, nil
}

// chainPreHook returns a HandlerFunc that invokes pre (if non-nil) before
// next. Used to install the Settings.OnCER / Settings.OnDWR hooks without
// changing the default handler.
func chainPreHook(pre diam.HandlerFunc, next diam.HandlerFunc) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		if pre != nil {
			pre(c, m)
		}
		// RFC 6733 §§5.3, 5.5, 5.6.1: a closed transport cannot
		// complete capabilities exchange or answer a watchdog request.
		if c.Closed() {
			return
		}
		next(c, m)
	}
}

// Settings return the Settings object used by this StateMachine.
func (sm *StateMachine) Settings() *Settings {
	return sm.cfg
}

// ServeDIAM implements the diam.Handler interface.
func (sm *StateMachine) ServeDIAM(c diam.Conn, m *diam.Message) {
	release := m.BeginDispatch()
	defer release()
	if headerErr := base.ValidateHeader(m); headerErr != nil {
		logMessage(c, m, slog.LevelWarn, "sm: invalid message header", headerErr)
		_ = sm.HandleMessageError(c, m, headerErr)
		return
	}
	if !sm.preCERMessageAllowed(c, m) {
		logMessage(c, m, slog.LevelWarn, "sm: message before CER; closing connection", nil)
		c.Close()
		return
	}
	if sm.cfg.ValidateRequests && m.Header.CommandFlags&diam.RequestFlag != 0 &&
		!sm.supportsApplicationOn(c, m.Header.ApplicationID) {
		// RFC 6733 §7.1.3: the applications this node advertises decide
		// 3007, not the dictionary that decoded the message, so this runs
		// before Validate and before AVP-level checks. HandleMessageError
		// also closes the connection of a rejected CER (§5.3).
		sm.handleUnsupportedCommand(c, m)
		return
	}
	if sm.cfg.RejectUnknownMandatoryAVPs && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if failed := m.UnknownMandatoryAVPs(); len(failed) != 0 {
			logMessage(c, m, slog.LevelWarn, "sm: unsupported mandatory AVP", &diam.MessageError{ResultCode: diam.AVPUnsupported})
			// RFC 6733 §7.1.5, Verified Erratum 4615: one Failed-AVP
			// contains the unsupported AVP(s), including Grouped hierarchy.
			_ = sm.writeErrorAnswer(c, m, diam.AVPUnsupported, failed, false)
			return
		}
	}
	if sm.cfg.ValidateRequests && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if validationErr := m.Validate(); validationErr != nil {
			logMessage(c, m, slog.LevelWarn, "sm: invalid request", validationErr)
			// RFC 6733 §§7.1, 7.2 and 7.5: only 3xxx protocol errors set E;
			// send one Failed-AVP container for the first AVP error.
			var failed []*diam.AVP
			if validationErr.FailedAVP != nil {
				failed = []*diam.AVP{validationErr.FailedAVP}
			}
			protocolError := validationErr.ResultCode >= 3000 && validationErr.ResultCode < 4000
			_ = sm.writeErrorAnswer(c, m, validationErr.ResultCode, failed, protocolError)
			return
		}
	}
	// RFC 6733 §5.6: finish CER/CEA before admitting the next callback.
	// Other admitted messages may execute application handlers concurrently.
	if m.Header.CommandCode != diam.CapabilitiesExchange {
		release()
	}
	if h, ok := sm.mux.Handler(m); ok {
		h.ServeDIAM(c, m)
	} else {
		sm.handleUnsupportedCommand(c, m)
	}
}

func (sm *StateMachine) preCERMessageAllowed(c diam.Conn, m *diam.Message) bool {
	value, ok := sm.accepted.Load(c)
	if !ok {
		// Dialed peers have CEA metadata. Without HandleAccept discovery,
		// enforce the same RFC 6733 §5.6.1 gate from handshake metadata.
		return admittedPeer(c) || m != nil && m.Header != nil &&
			m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
	}
	state := value.(*acceptedHandshake)
	state.mu.Lock()
	complete := state.complete
	state.mu.Unlock()
	// RFC 6733 §5.6.1: discard all non-CER traffic before CER/CEA succeeds.
	return complete || m != nil && m.Header != nil &&
		m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0
}

// HandleAccept implements diam.AcceptHandler for RFC 6733 §5.6.1 admission.
// The returned cleanup stops the timer and releases the connection on close.
func (sm *StateMachine) HandleAccept(c diam.Conn) func() {
	state := new(acceptedHandshake)
	sm.accepted.Store(c, state)
	d := sm.cfg.HandshakeTimeout
	if d == 0 {
		d = DefaultHandshakeTimeout
	}
	if d > 0 {
		state.timer = time.AfterFunc(d, func() {
			state.mu.Lock()
			complete := state.complete
			if !complete {
				state.timedOut = true
			}
			state.mu.Unlock()
			if !complete {
				logMessage(c, nil, slog.LevelWarn, "sm: handshake timeout; closing connection", nil)
				c.Close()
			}
		})
	}
	return func() {
		if state.timer != nil {
			state.timer.Stop()
		}
		sm.accepted.Delete(c)
	}
}

func (sm *StateMachine) completeAcceptedHandshake(c diam.Conn) bool {
	if value, ok := sm.accepted.Load(c); ok {
		state := value.(*acceptedHandshake)
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.timedOut {
			return false
		}
		state.complete = true
		if state.timer != nil {
			state.timer.Stop()
		}
	}
	return true
}

// Handle registers an application-agnostic command short name, or "ALL" for
// messages with no matching registration. Use HandleIdx to bind one application.
// Handlers run only after CER/CEA succeeds. Without ALL, unsupported requests
// receive 3001/3007 with E (RFC 6733 §§7.1.3, 7.2); unmatched answers are
// discarded. Both are logged. Handle panics for nil handlers, empty or duplicate
// names, and reserved CER, CEA, DWR, DPR and DPA commands.
func (sm *StateMachine) Handle(cmd string, handler diam.Handler) {
	if f, ok := handler.(diam.HandlerFunc); ok && f == nil {
		panic("sm: nil handler")
	}
	if handler == nil {
		panic("sm: nil handler")
	}
	sm.HandleFunc(cmd, handler.ServeDIAM)
}

// HandleIdx registers one application and command. It panics for nil handlers,
// duplicate indexes, or the base CER, CEA, DWR, DPR and DPA indexes.
func (sm *StateMachine) HandleIdx(cmd diam.CommandIndex, handler diam.Handler) {
	if f, ok := handler.(diam.HandlerFunc); ok && f == nil {
		panic("sm: nil handler")
	}
	if handler == nil {
		panic("sm: nil handler")
	}
	switch cmd {
	case baseCERIdx, baseCEAIdx, baseDWRIdx, baseDPRIdx, baseDPAIdx:
		panic(fmt.Sprintf("sm: cannot overwrite reserved command %v", cmd))
	default:
		sm.mux.HandleIdx(cmd, handshakeOK(handler.ServeDIAM))
	}
}

// HandleFunc is Handle for a handler function, with the same panic contract.
func (sm *StateMachine) HandleFunc(cmd string, handler diam.HandlerFunc) {
	if handler == nil {
		panic("sm: nil handler")
	}
	switch cmd {
	case "":
		panic("sm: empty command name")
	case "CER", "CEA", "DWR", "DPR", "DPA":
		panic("sm: cannot overwrite reserved command " + cmd)
	default:
		sm.mux.Handle(cmd, handshakeOK(handler))
	}
}

// handshakeOK is a wrapper for state machine handlers that only
// calls the designated handler function if the peer has passed the
// CER/CEA handshake.
type handshakeOK diam.HandlerFunc

// ServeDIAM implements the diam.Handler interface.
func (f handshakeOK) ServeDIAM(c diam.Conn, m *diam.Message) {
	if !admittedPeer(c) {
		// RFC 6733 §5.6.1: reject messages before capabilities exchange.
		logMessage(c, m, slog.LevelWarn, "sm: message before CER; closing connection", nil)
		c.Close()
		return
	}
	f(c, m)
}
