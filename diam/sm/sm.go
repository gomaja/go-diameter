// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// SupportedApp holds properties of each locally supported App
type SupportedApp struct {
	ID      uint32
	AppType string
	Vendor  uint32
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
		for _, vendor := range app.Vendor {
			addApp.Vendor = vendor.ID
		}
		locallySupportedApps = append(locallySupportedApps, addApp)
	}
	return locallySupportedApps
}

// Settings used to configure the state machine with AVPs to be added
// to CER on clients or CEA on servers.
type Settings struct {
	OriginHost  datatype.DiameterIdentity
	OriginRealm datatype.DiameterIdentity
	VendorID    datatype.Unsigned32
	ProductName datatype.UTF8String

	// OriginStateID is optional for clients and servers and is omitted if unset.
	// RFC 6733 §8.16 requires it to reflect this entity's Origin-Host.
	//
	// May be set to datatype.Unsigned32(time.Now().Unix()).
	OriginStateID datatype.Unsigned32

	// FirmwareRevision is optional, and not added if unset.
	FirmwareRevision datatype.Unsigned32

	// HostIPAddress is optional for both clients and servers, when not set local
	// host IP address is used.
	//
	// This property may be set when the IP address of the host sending/receiving
	// the request is different from the configured allowed IPs in the other end,
	// for example when using a VPN or a gateway.
	//
	HostIPAddresses []datatype.Address
	//
	// Deprecated: HostIPAddress is depreciated, use HostIPAddresses instead
	HostIPAddress datatype.Address

	// Dict governs advertised applications and CER application validation
	// (RFC 6733 §5.3). If nil, advertising uses dict.Default and validation
	// uses the received message's dictionary.
	Dict *dict.Parser

	// OnCER, if non-nil, is invoked when a CER is received, before the
	// state machine processes it. Useful for logging, metrics, or access
	// control. The default handshake logic runs after OnCER returns.
	// Closing the connection from the hook is honored and aborts the
	// handshake.
	OnCER diam.HandlerFunc

	// OnCEA, if non-nil, is invoked immediately before a CEA is sent (both
	// the success CEA and the error CEA). Useful for logging or metrics.
	OnCEA diam.HandlerFunc

	// OnDWR, if non-nil, is invoked when a DWR is received (after the
	// peer has passed the handshake) before the state machine responds
	// with DWA. Same semantics as OnCER.
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
	// Dialed connections are unaffected. Wrappers must forward diam.AcceptHandler;
	// otherwise both the pre-CER message gate and this timeout are disabled.
	HandshakeTimeout time.Duration
}

// DefaultHandshakeTimeout applies when Settings.HandshakeTimeout is zero.
// RFC 6733 §5.6.1 permits an implementation-defined pre-CER timeout.
const DefaultHandshakeTimeout = 30 * time.Second

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
type StateMachine struct {
	cfg           *Settings
	mux           *diam.ServeMux
	hsNotifyc     chan diam.Conn // handshake notifier
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
func New(settings *Settings) *StateMachine {
	if len(settings.HostIPAddresses) == 0 && len(settings.HostIPAddress) > 0 {
		settings.HostIPAddresses = []datatype.Address{settings.HostIPAddress}
	}
	dp := settings.Dict
	if dp == nil {
		dp = dict.Default
	}
	sm := &StateMachine{
		cfg:           settings,
		mux:           diam.NewServeMux(),
		hsNotifyc:     make(chan diam.Conn, 1000),
		supportedApps: PrepareSupportedApps(dp),
		dictionary:    settings.Dict,
	}
	cerHandler := chainPreHook(settings.OnCER, handleCER(sm))
	dwrHandler := chainPreHook(settings.OnDWR, handleDWR(sm))
	sm.mux.Handle("CER", cerHandler)
	sm.mux.Handle("DWR", handshakeOK(dwrHandler))
	sm.mux.Handle("DPR", handshakeOK(handleDPR(sm)))
	sm.mux.Handle("DPA", handshakeOK(handleDPA(sm)))
	sm.mux.HandleIdx(baseCERIdx, cerHandler)
	sm.mux.HandleIdx(baseDWRIdx, dwrHandler)
	sm.mux.Handle("ALL", diam.HandlerFunc(sm.handleUnsupportedCommand))
	sm.mux.HandleIdx(baseDPRIdx, handshakeOK(handleDPR(sm)))
	sm.mux.HandleIdx(baseDPAIdx, handshakeOK(handleDPA(sm)))
	return sm
}

// chainPreHook returns a HandlerFunc that invokes pre (if non-nil) before
// next. Used to install the Settings.OnCER / Settings.OnDWR hooks without
// changing the default handler.
func chainPreHook(pre diam.HandlerFunc, next diam.HandlerFunc) diam.HandlerFunc {
	if pre == nil {
		return next
	}
	return func(c diam.Conn, m *diam.Message) {
		pre(c, m)
		next(c, m)
	}
}

// Settings return the Settings object used by this StateMachine.
func (sm *StateMachine) Settings() *Settings {
	return sm.cfg
}

// ServeDIAM implements the diam.Handler interface.
func (sm *StateMachine) ServeDIAM(c diam.Conn, m *diam.Message) {
	if !sm.preCERMessageAllowed(c, m) {
		c.Close()
		return
	}
	if sm.cfg.RejectUnknownMandatoryAVPs && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if failed := m.UnknownMandatoryAVPs(); len(failed) != 0 {
			// RFC 6733 §7.1.5, Verified Erratum 4615: one Failed-AVP
			// contains the unsupported AVP(s), including Grouped hierarchy.
			if err := sm.writeErrorAnswer(c, m, diam.AVPUnsupported, failed, false); err != nil {
				sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			}
			return
		}
	}
	if sm.cfg.ValidateRequests && m.Header.CommandFlags&diam.RequestFlag != 0 {
		if validationErr := m.Validate(); validationErr != nil {
			// RFC 6733 §§7.1, 7.2 and 7.5: only 3xxx protocol errors set E;
			// send one Failed-AVP container for the first AVP error.
			var failed []*diam.AVP
			if validationErr.FailedAVP != nil {
				failed = []*diam.AVP{validationErr.FailedAVP}
			}
			protocolError := validationErr.ResultCode >= 3000 && validationErr.ResultCode < 4000
			if err := sm.writeErrorAnswer(c, m, validationErr.ResultCode, failed, protocolError); err != nil {
				sm.Error(&diam.ErrorReport{Conn: c, Message: m, Error: err})
			}
			return
		}
	}
	sm.mux.ServeDIAM(c, m)
}

func (sm *StateMachine) preCERMessageAllowed(c diam.Conn, m *diam.Message) bool {
	value, ok := sm.accepted.Load(c)
	if !ok {
		return true // dialed connection
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

// Handle implements the diam.Handler interface.
func (sm *StateMachine) Handle(cmd string, handler diam.Handler) {
	sm.HandleFunc(cmd, handler.ServeDIAM)
}

func (sm *StateMachine) HandleIdx(cmd diam.CommandIndex, handler diam.Handler) {
	switch cmd {
	case baseCERIdx, baseCEAIdx, baseDWRIdx, baseDPRIdx, baseDPAIdx:
		sm.Error(&diam.ErrorReport{
			Error: fmt.Errorf("cannot overwrite %v command in the state machine", cmd),
		})
	default:
		sm.mux.HandleIdx(cmd, handshakeOK(handler.ServeDIAM))
	}
}

// HandleFunc implements the diam.Handler interface.
func (sm *StateMachine) HandleFunc(cmd string, handler diam.HandlerFunc) {
	switch cmd {
	case "CER", "CEA", "DWR", "DPR", "DPA":
		sm.Error(&diam.ErrorReport{
			Error: fmt.Errorf("cannot overwrite %s command in the state machine", cmd),
		})
	default:
		sm.mux.Handle(cmd, handshakeOK(handler))
	}
}

// Error implements the diam.ErrorReporter interface.
func (sm *StateMachine) Error(err *diam.ErrorReport) {
	sm.mux.Error(err)
}

// ErrorReports implement the diam.ErrorReporter interface.
func (sm *StateMachine) ErrorReports() <-chan *diam.ErrorReport {
	return sm.mux.ErrorReports()
}

// HandshakeNotify implements the HandshakeNotifier interface.
func (sm *StateMachine) HandshakeNotify() <-chan diam.Conn {
	return sm.hsNotifyc
}

// The HandshakeNotifier interface is implemented by Handlers
// that allow detecting peers that have passed the CER/CEA
// handshake.
type HandshakeNotifier interface {
	// HandshakeNotify returns a channel that receives
	// a peer's diam.Conn after it passes the handshake.
	HandshakeNotify() <-chan diam.Conn
}

// handshakeOK is a wrapper for state machine handlers that only
// calls the designated handler function if the peer has passed the
// CER/CEA handshake.
type handshakeOK diam.HandlerFunc

// ServeDIAM implements the diam.Handler interface.
func (f handshakeOK) ServeDIAM(c diam.Conn, m *diam.Message) {
	if _, ok := smpeer.FromContext(c.Context()); ok {
		f(c, m)
	}
}
