package diam

import (
	"errors"
	"fmt"
)

// TransportRestartError is an ordered, nonterminal read boundary for an SCTP
// association restart (RFC 9260 §5.2.4; RFC 6458 §6.1.1). Reads may resume after
// the caller discards the interrupted message and retires the old connection.
type TransportRestartError struct {
	AssociationID                   uint32
	InboundStreams, OutboundStreams uint16
}

func (e *TransportRestartError) Error() string {
	return fmt.Sprintf("diam: SCTP association %d restarted (%d inbound, %d outbound streams)", e.AssociationID, e.InboundStreams, e.OutboundStreams)
}

// RetirementReason identifies why an accepted connection generation ended.
type RetirementReason uint8

const (
	SCTPAssociationRestart RetirementReason = iota + 1
	AcceptedCERRenewal
)

// ErrConnectionRetired identifies writes fenced by generation retirement.
// Such errors also match net.ErrClosed.
var ErrConnectionRetired = errors.New("diam: connection generation retired")

// ConnLifecycle describes a generation of one physical connection. Discover it
// through ConnAs. Generation starts at one and increases on accepted renewal.
type ConnLifecycle interface {
	Generation() uint64
	RetirementReason() RetirementReason
}

// RetireHandler stops old protocol admission and write production before a new
// accepted generation is created. Server discovers it through HandlerAs and
// bounds retirement to one second. It must return promptly; business callbacks
// may finish later. Handlers without this interface cause SCTP restart closure.
type RetireHandler interface {
	HandleRetire(Conn, RetirementReason) error
}

// AcceptedCERHandler permits opt-in CER renewal on an admitted, non-Closing
// accepted connection. CanRenewAcceptedCER is a pure eligibility check, called
// in message admission order before dispatch. Discover it through HandlerAs.
type AcceptedCERHandler interface {
	CanRenewAcceptedCER(Conn) bool
}
