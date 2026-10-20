// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/protocol"

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
// admission internally. EnableWatchdog opts accepted connections into RFC 3539
// supervision. See StateMachine for the middleware contract.
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
	// to the message dictionary when needed (RFC 6733 §5.3). Nil transport
	// dictionaries use the shared, initially base-only dict.Default. Supply
	// the same selected parser here and on the client or server for application
	// decoding, validation, and capability inference.
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

	// OnProtocolError observes handled protocol conditions (RFC 6733 §§5–7),
	// including discards and closing decisions, independently of logging. Calls
	// run synchronously after existing handling and logs, without a queue. Return
	// promptly: blocking delays that worker, admission and possibly closure.
	// Concurrent dispatch and timers may call concurrently for the same Conn.
	// c.Close is safe; do not wait for later input, call Disconnect, or wait for
	// Manager.Close or shutdown from this callback. A panic is logged and recovered
	// without changing the selected protocol action. Configure before use.
	// Metadata and errors are detached; the Conn identifies the deciding generation.
	// Already admitted work can notify after closure or retirement with that Conn.
	// Nil performs no notification work. peer.Manager honours this setting too.
	OnProtocolError func(diam.ProtocolErrorEvent)

	// OnCER, if non-nil, observes an initial CER after header, body and
	// request validation, before the default handshake logic runs. On an
	// Open connection it observes a decodable repeated CER with valid header
	// bits, even if its body is invalid; the CER is discarded after the hook.
	// External admission through smpeer.Metadata without a CEA consumes such
	// repeated CERs silently, without invoking OnCER.
	// CERs with invalid header bits never reach OnCER. T and reserved bits
	// do not prevent a repeated CER from reaching it. Useful for logging,
	// metrics, or access control.
	// Calling c.Close() from the hook aborts the handshake without publishing
	// peer metadata, admitting the peer, building a CEA, or calling OnCEA or
	// OnHandshake. A connection wrapper's Close must call the wrapped Close.
	// Closing c.Connection() directly is not detected by this hook contract.
	// On accepted and dialed connections, changing the command, application, direction or either
	// identifier is a local protocol error: the connection closes and an Error
	// record is logged. AVP changes retain the normal validation path.
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
	// On accepted and dialed connections, changing the command, application, direction or either
	// identifier closes the connection and logs an Error record, as for OnCER.
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
	// application dictionaries may be incomplete. The six connection-level
	// base messages are always validated, including their answers.
	ValidateRequests bool

	// OnDPR observes a validated peer DPR and its Disconnect-Cause after the
	// DPA is sent. Callers decide whether to reconnect (RFC 6733 §5.4.3).
	OnDPR func(diam.Conn, DisconnectCause)

	// DPRCloseTimeout bounds the receiver's Closing state (RFC 6733 §5.6).
	// Zero uses 5 seconds.
	DPRCloseTimeout time.Duration

	// EnableWatchdog supervises connections accepted by this StateMachine after
	// a success CEA and OnHandshake return. It defaults to false. Conforming
	// deployments should enable it (RFC 6733 §5.5.3; RFC 3539 §3.4).
	// Client.EnableWatchdog independently supervises dialed connections.
	// Supervised DWAs are consumed here and do not reach a user "DWA" route.
	// After supervision ends, late DWAs follow normal dispatch; without a
	// matching route they are logged as unhandled answers.
	// After peer FIN, DispatchDone waits for in-flight concurrent handlers;
	// supervision and its events may continue for that departing peer meanwhile.
	EnableWatchdog bool

	// WatchdogInterval is RFC 3539 §3.4.1 [1] Twinit: zero uses 30 seconds,
	// the minimum is 6 seconds, and each timer reset adds ±2 seconds of jitter.
	// New validates it only when EnableWatchdog is set, without changing it.
	WatchdogInterval time.Duration

	// WatchdogStream selects the outgoing SCTP DWR stream; zero is the default.
	// It is ignored on TCP (RFC 6733 §2.1.1).
	WatchdogStream uint

	// OnWatchdogConnEvent observes watchdog outcomes for each accepted connection.
	// SUSPECT reports failover; StateMachine has no pending-request queue or
	// routing policy (RFC 3539 §3.4.1 [3]; RFC 6733 §5.5.4). DOWN closes the
	// connection on the next expiry (RFC 3539 Appendix A).
	// Calls for one connection are serialized; different connections may call
	// concurrently. Return promptly. Do not call Disconnect synchronously or wait
	// for any inbound message on this connection from the hook; both can deadlock.
	// Stopping for DPR prevents further callbacks (RFC 6733 §5.6 Closing).
	// A panic is logged and closes only the affected connection.
	OnWatchdogConnEvent func(diam.Conn, WatchdogEvent)

	watchdogTiming *watchdogTiming // test-only short Tw and deterministic jitter

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
// Settings.EnableWatchdog supervises each successful accepted connection using
// RFC 3539 §3.4.1 and Appendix A. Conforming deployments should enable it
// (RFC 6733 §5.5.3). Dialed connections use Client.EnableWatchdog instead.
// Choose Twinit to tolerate handler latency: saturating MaxConcurrentHandlers
// stops the reader and can delay DWA processing (RFC 3539 §3.4).
// Server.WriteTimeout bounds socket writes, including DWR; it does not bound
// callbacks or custom Conn wrappers. A blocked DWR write delays publication
// and its observer; core receipt, credit, deadlines and retirement still run.
// Disconnect/DPR joins earlier watchdog work until closure or its deadline.
// OnWatchdogConnEvent must not call Disconnect synchronously or wait for any
// inbound message on the same connection; both can deadlock.
// Connection wrappers must retain the same Conn value across messages;
// supervision and Disconnect track connections by that identity. A Conn that
// offers no closure signal (neither DispatchDone nor CloseNotify, directly or
// through Unwrap, or one returning a nil channel) keeps its protocol state in
// its context, like the peer metadata: Context must return what SetContext
// last stored, and code that replaces it must derive the new context from
// Context() at that moment, not from a value read before the StateMachine
// handled a message.
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
	supportedApps []*SupportedApp
	dictionary    *dict.Parser
	cores         sync.Map   // diam.Conn -> per-generation accepted core
	contextCores  sync.Mutex // serializes cores kept in a Conn's context
	accepted      sync.Map   // diam.Conn -> *acceptedHandshake
	watchdog      *watchdogPolicy
}

// New creates and initializes a new StateMachine for clients or servers.
// See Settings.Dict for the advertising and validation dictionaries.
func New(settings *Settings) (*StateMachine, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	policy, err := acceptedWatchdogPolicy(settings)
	if err != nil {
		return nil, err
	}
	dp := settings.Dict
	if dp == nil {
		dp = dict.Default
	}
	sm := &StateMachine{
		cfg:           settings,
		watchdog:      policy,
		mux:           diam.NewServeMux(),
		supportedApps: PrepareSupportedApps(dp),
		dictionary:    settings.Dict,
	}
	cerHandler := diam.HandlerFunc(sm.ServeDIAM)
	dwrHandler := diam.HandlerFunc(sm.ServeDIAM)
	sm.mux.Handle("CER", cerHandler)
	sm.mux.Handle("DWR", dwrHandler)
	sm.mux.Handle("DPR", diam.HandlerFunc(sm.ServeDIAM))
	sm.mux.Handle("DPA", diam.HandlerFunc(sm.ServeDIAM))
	sm.mux.HandleIdx(baseCERIdx, cerHandler)
	sm.mux.HandleIdx(baseDWRIdx, dwrHandler)
	sm.mux.HandleIdx(baseDPRIdx, diam.HandlerFunc(sm.ServeDIAM))
	sm.mux.HandleIdx(baseDPAIdx, diam.HandlerFunc(sm.ServeDIAM))
	return sm, nil
}

// Settings return the Settings object used by this StateMachine.
func (sm *StateMachine) Settings() *Settings {
	return sm.cfg
}

// ServeDIAM implements the diam.Handler interface.
func (sm *StateMachine) ServeDIAM(c diam.Conn, m *diam.Message) {
	release := m.BeginDispatch()
	defer release()
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok && lifecycle.RetirementReason() != 0 {
		return
	}
	if s := sm.acceptedCore(c, m, true); s != nil {
		batch := s.prepare(protocol.Input{Kind: protocol.Receive, Message: m})
		s.run(batch)
		return
	}

}

// HandleAccept implements diam.AcceptHandler for RFC 6733 §5.6.1 admission.
// The returned cleanup stops the timer and releases the connection on close.
func (sm *StateMachine) HandleAccept(c diam.Conn) func() {
	s := sm.acceptedCore(c, nil, true)
	if s == nil {
		return func() {}
	}
	sm.accepted.Store(c, s)
	return func() {
		s.apply(protocol.Input{Kind: protocol.TransportLost})
		sm.accepted.CompareAndDelete(c, s)
		sm.cores.CompareAndDelete(c, s)
	}
}

// HandleRetire invalidates the core without joining a writer or observer.
// RFC 6733 §§5.5.4,5.6; RFC 3539 Appendix A.
func (sm *StateMachine) HandleRetire(c diam.Conn, reason diam.RetirementReason) error {
	if s := sm.acceptedCore(c, nil, false); s != nil {
		s.apply(protocol.Input{Kind: protocol.Retire, Reason: reason})
		sm.accepted.CompareAndDelete(c, s)
		if w := s.watchdogState(); w != nil {
			w.latchStop()
		}
	}
	return nil
}

// CanRenewAcceptedCER consults the generation core's admission and phase.
// This is opt-in compatibility, not RFC 6737 capabilities-update support.
func (sm *StateMachine) CanRenewAcceptedCER(c diam.Conn) bool {
	if c.Closed() {
		return false
	}
	if _, accepted := sm.accepted.Load(c); !accepted {
		return false
	}
	if s := sm.acceptedCore(c, nil, false); s != nil {
		return s.readyOpen()
	}
	return false
}
func (sm *StateMachine) acceptedClosing(c diam.Conn) bool {
	if s := sm.acceptedCore(c, nil, false); s != nil {
		return s.phase() >= protocol.Closing
	}
	return false
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

// Application callbacks also require the peer metadata in the public context.
// A caller can replace that context after genuine admission; the core's bound
// identity remains immutable while this callback gate follows the context.
type handshakeOK diam.HandlerFunc

func (f handshakeOK) ServeDIAM(c diam.Conn, m *diam.Message) {
	if !admittedPeer(c) {
		logMessage(c, m, slog.LevelWarn, "sm: message before CER; closing connection", nil)
		c.Close()
		return
	}
	f(c, m)
}
