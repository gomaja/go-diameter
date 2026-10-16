// Package protocol owns the Diameter base protocol for one connection generation.
// Callers serialize Handle and Snapshot, perform effects outside their state
// locks, and return completions with the exact connection and operation tokens.
// No method performs transport I/O, schedules timers, or invokes callbacks.
package protocol

import (
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

// Connection distinguishes separate connections even when their generations tie.
type Connection struct{ Instance, Generation uint64 }
type Role uint8

const (
	Responder Role = iota + 1
	Initiator
)

type Phase uint8

const (
	PreCER Phase = iota
	WaitCEA
	Open
	Closing
	Closed
	Retired
)

// Config is copied by New. ResolveHostIPAddresses must be nil: address discovery
// belongs outside mutation. Zero handshake timeout disables accepted admission's
// deadline. QueueWrites selects queued versus completed-write accounting.
type Config struct {
	ValidateRequests, RejectUnknownMandatoryAVPs  bool
	Connection                                    Connection
	Role                                          Role
	Dictionary                                    *dict.Parser
	Local                                         base.Settings
	ExpectedHost                                  string
	TLS, QueueWrites, Hooks                       bool
	HandshakeTimeout, CERInterval, ClosingTimeout time.Duration
	MaxRetransmits                                uint
	Watchdog                                      bool
	WatchdogInterval                              time.Duration
	Recovery                                      bool
	// StateMachine's synchronous Disconnect may start after a peer DPR. Its
	// caller deadline is independent of the peer-initiated Closing deadline.
	LocalDisconnectInClosing bool
	// StateMachine applies its shared parser's post-OnDWR discard/result
	// contract. Wire grammar is validated before selecting the hook (§5.5.1).
	DWRHookCompatibility bool
	// Client keeps its CER response window after EOF. With retries left,
	// the next write's actual error completes the handshake; otherwise the
	// response timer reports timeout. This does not govern accepted peers.
	CERTransportLossCompatibility bool
}

// Reservation identifies a lease in the caller's shared application/control ID
// space. Zero wire identifiers are valid; the allocator supplies a nonzero Token.
type Reservation struct {
	Token    uint64
	Hop, End uint32
}

// Allocator is implemented by the effect executor, never called by the core.
// Release drops logical ownership. Executors must also pin each selected writer
// until it returns or skips publication, so early answers cannot cause ID reuse.
type Allocator interface {
	Reserve(Connection, uint32) (Reservation, error)
	Release(Reservation)
}

type InputKind uint8

const (
	Start InputKind = iota
	Receive
	Continue
	Activate
	RejectCandidate
	ReleaseAdmission
	ReserveResult
	WriteResult
	Frozen
	TimerExpired
	Disconnect
	Unhandled
	Abort
	TransportLost
	Retire
	StopSupervision
)

type WriteStage uint8

const (
	QueueStage WriteStage = iota
	WrittenStage
	// SkippedStage is a terminal result proving that a control attempt never
	// passed the native publication gate. Err may retain the gate's reason;
	// it is not a transport failure. Required replies still require delivery.
	SkippedStage
)

type TimerKind uint8

const (
	HandshakeTimer TimerKind = iota
	RetryTimer
	WatchdogTimer
	ClosingTimer
	ReceiverDisconnectTimer
	timerCount
)

// Input carries one event. At and Sequence are recorded at admission, not after
// queue processing. Timer expiries include an AfterReceive barrier. Ownership is
// an adapter-owned claim ticket, checked atomically again before answer delivery.
// WriteResult must include the post-hook ExpectedBytes and ReplyCode. Every Send
// needs a terminal result, including skipped and queue-rejected writes.
type Input struct {
	// Resolved outside the core mutex before the first CER is built.
	RefreshLocalAddresses        bool
	LocalAddresses               []datatype.Address
	Kind                         InputKind
	Connection                   Connection
	At                           time.Time
	Sequence, AfterReceive       uint64
	Token                        uint64
	Message                      *diam.Message
	Error                        *diam.MessageError
	ErrorInput                   bool // frontend message-error callback, including a nil description
	Err                          error
	Reservation                  Reservation
	Stage                        WriteStage
	Bytes, ExpectedBytes         int64
	ReplyCode, ResultCode, Cause uint32
	Timer                        TimerKind
	Interval, Timeout            time.Duration
	InFlight, TransportClosed    bool
	HasHandler                   bool // frontend route lookup; control handling remains core-owned
	Unhandled                    bool // frontend handler discovery; the core selects unsupported-command disposition
	Ownership                    uint64
	Reason                       diam.RetirementReason
}

type EffectKind uint8

const (
	ReserveIDs EffectKind = iota
	ReleaseIDs
	Send
	Publish
	ValidatedCER
	RunHook
	HandshakeReady
	Admit
	Hold
	Discard
	Notify
	ArmTimer
	StopTimer
	FreezeAdmission
	Close
	CancelSend
	CompleteRequest
	// PeerDisconnectDecision is immediate internal policy bookkeeping, not a
	// public callback. Cause is the first validated DPR's Disconnect-Cause.
	PeerDisconnectDecision
)

type NoticeKind uint8

const (
	ProtocolNotice NoticeKind = iota
	HandshakeNotice
	DisconnectNotice
	PeerDisconnectNotice
	WatchdogNotice
)

type Outcome uint8

const (
	Completed Outcome = iota
	TimedOut
	ConnectionClosed
	Cancelled
	NotOpen
	AlreadyPending
)

// Protocol observer notifications contain metadata without message payloads;
// handshake completions additionally carry detached semantic parser results.
// Reply status is measured at the owner's reporting boundary; a later queued
// write failure is separate.
// Executors serialize observer delivery across batches: a queued notification's
// callback must return before a later failure callback. Callback execution never
// holds the core's mutation lock or prevents timer/lifecycle Handle calls.
type Notification struct {
	CauseError                   error  // detached diagnostic cause; public events retain kind/result metadata
	Diagnostic                   string // frontend log detail selected with the protocol decision
	Kind                         NoticeKind
	Protocol                     diam.ProtocolErrorKind
	ResultCode, ReplyCode, Cause uint32
	Reply                        diam.ProtocolReplyStatus
	Closing                      bool
	Outcome                      Outcome
	Watchdog                     watchdog.State
	Message                      diam.ProtocolMessageMetadata
	// Handshake carries semantic completion data independently of observer
	// classification. Accessors return detached parser errors and CEA fields.
	Handshake HandshakeResult
}

// Effect is a tagged obligation. Message and Snapshot payloads are detached from
// core-owned storage. Hold requires the runner to retain/replay Input in order.
// RunHook resumes through Continue; HandshakeReady through ReleaseAdmission.
// FreezeAdmission is bounded bookkeeping in the same admission transaction:
// freeze diam.PendingRequests and the frontend drain set, then feed Frozen
// before exposing sends. No blocking write or callback belongs in that lock.
type Effect struct {
	Kind EffectKind
	// ReleaseDispatch ends native receive admission after this decision commits,
	// before callbacks or writes. CER and rejected requests retain their barrier
	// through handshake/reply completion (RFC 6733 §5.6).
	ReleaseDispatch bool
	Connection      Connection
	Token           uint64
	Command         uint32
	Reservation     Reservation
	Message         *diam.Message
	// AnswerHook marks a normal DWR response eligible for the DWA hook.
	// Validation and decoding error replies retain their automatic reply path.
	AnswerHook           bool
	Required, CloseAfter bool
	Stage                WriteStage
	Notification         Notification
	Timer                TimerKind
	Deadline             time.Time
	Snapshot             Snapshot
	Input                Input
	Ownership            uint64
	Cause                uint32
}

// Capabilities keeps local advertisement separate from the remote offer and
// negotiated intersection. CER/CEA contain copied exported parse fields;
// RemoteApplications retains the complete remote offer without reparsing.
type Capabilities struct {
	Local                                                     base.Settings
	CER                                                       *base.CER
	CEA                                                       *base.CEA
	LocalApplications, RemoteApplications, CommonApplications []uint32
	// ParsedApplications retains the validated CER parser's locally recognized
	// IDs, including their original order and duplicates, for frontend metadata.
	ParsedApplications []uint32
	Host, Realm        string
	// TLS records established transport security (RFC 6733 §§5.3,6.10).
	// Capability exchange does not initiate or renegotiate transport security.
	TLS bool
}
type TimerSnapshot struct {
	Token    uint64
	Deadline time.Time
}
type ControlSnapshot struct {
	Command           uint32
	Reservation       Reservation
	Logical, Answered bool
	Writers           int
}

// Snapshot is an immutable value. Slice/AVP-bearing accessors return fresh copies.
type Snapshot struct {
	phase                Phase
	connection           Connection
	role                 Role
	candidate, admission uint64
	ready, frozen        bool
	capabilities         Capabilities
	wd                   watchdog.Machine
	timers               [timerCount]TimerSnapshot
	controls             []ControlSnapshot
	peerCause            uint32
	peerDPR              bool
	handshake            HandshakeResult
}

func (s Snapshot) Handshake() HandshakeResult { return s.handshake }

// PeerDisconnect retains the first validated peer cause across send failure,
// transport loss and retirement. The bool distinguishes REBOOTING (zero) from
// no DPR; public PeerDisconnectNotice delivery remains tied to the DPA send.
func (s Snapshot) PeerDisconnect() (uint32, bool) { return s.peerCause, s.peerDPR }

func (s Snapshot) Phase() Phase               { return s.phase }
func (s Snapshot) Connection() Connection     { return s.connection }
func (s Snapshot) Role() Role                 { return s.role }
func (s Snapshot) Candidate() uint64          { return s.candidate }
func (s Snapshot) Admission() uint64          { return s.admission }
func (s Snapshot) Ready() bool                { return s.ready }
func (s Snapshot) Frozen() bool               { return s.frozen }
func (s Snapshot) Watchdog() watchdog.Machine { return s.wd }
func (s Snapshot) Timer(k TimerKind) TimerSnapshot {
	if k >= timerCount {
		return TimerSnapshot{}
	}
	return s.timers[k]
}
func (s Snapshot) Controls() []ControlSnapshot { return append([]ControlSnapshot(nil), s.controls...) }
