// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam/internal/observe"
)

// ProtocolErrorKind classifies a protocol condition absorbed by a handler.
// It implements error so errors.Is can match a ProtocolError's kind.
type ProtocolErrorKind string

const (
	// ProtocolReplyFailure identifies a required answer that could not be
	// built, queued or completely written. Closing is the local failure policy;
	// it does not classify the received request as invalid.
	ProtocolReplyFailure ProtocolErrorKind = "reply_failure"
	// ProtocolMalformedMessage identifies a decoding failure (RFC 6733 §§3,
	// 4 and 7.1.5; Verified Errata ID 3805 clarifies Message Length units).
	ProtocolMalformedMessage ProtocolErrorKind = "malformed_message"
	// ProtocolInvalidHeader identifies an invalid base-command header
	// (RFC 6733 §§2.5 and 7.1.3).
	ProtocolInvalidHeader ProtocolErrorKind = "invalid_header"
	// ProtocolUnsupportedAVP identifies an unsupported mandatory AVP
	// (RFC 6733 §§4.1 and 7.1.5; Verified Errata ID 4615 requires one
	// Failed-AVP container for all offending AVPs).
	ProtocolUnsupportedAVP ProtocolErrorKind = "unsupported_avp"
	// ProtocolInvalidRequest identifies a request grammar or AVP validation
	// failure (RFC 6733 §§3.2, 4.1, 4.4, 7.1 and 7.5).
	ProtocolInvalidRequest ProtocolErrorKind = "invalid_request"
	// ProtocolUnsupportedCommand identifies an unsupported command
	// (RFC 6733 §§7.1.3 and 7.2).
	ProtocolUnsupportedCommand ProtocolErrorKind = "unsupported_command"
	// ProtocolUnsupportedApplication identifies an unsupported application
	// (RFC 6733 §§5.3 and 7.1.3).
	ProtocolUnsupportedApplication ProtocolErrorKind = "unsupported_application"
	// ProtocolInvalidDWR identifies an invalid Device-Watchdog-Request
	// (RFC 6733 §5.5.1).
	ProtocolInvalidDWR ProtocolErrorKind = "invalid_dwr"
	// ProtocolInvalidDWA identifies an invalid Device-Watchdog-Answer
	// (RFC 6733 §5.5.2).
	ProtocolInvalidDWA ProtocolErrorKind = "invalid_dwa"
	// ProtocolRejectedDWA identifies a Device-Watchdog-Answer with a
	// non-success Result-Code (RFC 6733 §§5.5.2 and 7.1).
	ProtocolRejectedDWA ProtocolErrorKind = "rejected_dwa"
	// ProtocolInvalidDPR identifies an invalid Disconnect-Peer-Request
	// (RFC 6733 §5.4.1).
	ProtocolInvalidDPR ProtocolErrorKind = "invalid_dpr"
	// ProtocolInvalidDPA identifies an invalid Disconnect-Peer-Answer
	// (RFC 6733 §§5.4.2 and 5.6).
	ProtocolInvalidDPA ProtocolErrorKind = "invalid_dpa"
	// ProtocolUnexpectedMessage identifies a discarded unexpected message,
	// including an unmatched or duplicate answer; it does not establish peer
	// misconduct (RFC 6733 §§5.3, 5.6 and 6.2.1).
	ProtocolUnexpectedMessage ProtocolErrorKind = "unexpected_message"
	// ProtocolHandshakeState identifies a message rejected in the current
	// capabilities-exchange state (RFC 6733 §5.6).
	ProtocolHandshakeState ProtocolErrorKind = "handshake_state"
	// ProtocolCERRejected identifies a rejected Capabilities-Exchange-Request
	// (RFC 6733 §§5.3, 6.10 and 7.1.5).
	ProtocolCERRejected ProtocolErrorKind = "cer_rejected"
	// ProtocolHandshakeTimeout identifies a capabilities-exchange timeout
	// (RFC 6733 §5.6).
	ProtocolHandshakeTimeout ProtocolErrorKind = "handshake_timeout"
	// ProtocolCEARejected identifies a rejected Capabilities-Exchange-Answer
	// (RFC 6733 §5.3.2).
	ProtocolCEARejected ProtocolErrorKind = "cea_rejected"
	// ProtocolPeerRejected identifies a Disconnect-Peer-Answer with a
	// non-success Result-Code (RFC 6733 §§5.4.2 and 5.6).
	ProtocolPeerRejected ProtocolErrorKind = "peer_rejected"
	// ProtocolDisconnectTimeout identifies a disconnect or Wait-Returns
	// timeout (RFC 6733 §5.6).
	ProtocolDisconnectTimeout ProtocolErrorKind = "disconnect_timeout"
	// ProtocolWatchdogTimeout identifies watchdog failure that closes a
	// connection (RFC 6733 §5.5.3; RFC 3539 §3.4.1).
	ProtocolWatchdogTimeout ProtocolErrorKind = "watchdog_timeout"
)

// Error returns the kind's stable classification string.
func (k ProtocolErrorKind) Error() string { return string(k) }

// ProtocolError is an immutable classification of a handled protocol condition.
// It retains no message, AVP, dictionary, context or original parser error.
// errors.As finds *ProtocolError; errors.Is matches its ProtocolErrorKind.
type ProtocolError struct {
	kind       ProtocolErrorKind
	resultCode uint32
}

// NewProtocolError creates a classification with an associated Result-Code.
// The code describes the detected condition or rejected incoming answer;
// zero means unavailable. It need not equal ProtocolErrorEvent.ReplyCode.
func NewProtocolError(kind ProtocolErrorKind, resultCode uint32) *ProtocolError {
	return &ProtocolError{kind: kind, resultCode: resultCode}
}

// Kind returns the protocol condition's classification.
func (e *ProtocolError) Kind() ProtocolErrorKind {
	if e == nil {
		return ""
	}
	return e.kind
}

// ResultCode returns the condition's associated Result-Code, or zero if unknown.
func (e *ProtocolError) ResultCode() uint32 {
	if e == nil {
		return 0
	}
	return e.resultCode
}

// Error returns a diagnostic description of the condition.
func (e *ProtocolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.resultCode == 0 {
		return "diameter protocol error: " + string(e.kind)
	}
	return fmt.Sprintf("diameter protocol error: %s (result code %d)", e.kind, e.resultCode)
}

// Unwrap returns the kind so errors.Is can classify a wrapped ProtocolError.
func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.kind
}

// ProtocolMessageMetadata is a value snapshot safe to retain after a callback.
// It contains no AVP payloads or references to a live Message.
type ProtocolMessageMetadata struct {
	// Header is a copy of the offending message's header (RFC 6733 §3).
	Header Header
	// HasHeader reports whether Header is available. Timer events have none.
	HasHeader bool
	// Stream is the offending message's receive stream, if applicable.
	Stream uint
}

// ProtocolReplyStatus describes the progress of a selected required answer.
type ProtocolReplyStatus uint8

const (
	// ProtocolReplyNone means no answer was selected.
	ProtocolReplyNone ProtocolReplyStatus = iota
	// ProtocolReplyQueued means a writer queue accepted the answer. Closing
	// the connection from the callback may prevent its transmission.
	ProtocolReplyQueued
	// ProtocolReplyWritten means WriteTo succeeded, not that the peer received it.
	ProtocolReplyWritten
	// ProtocolReplyFailed means building, enqueuing or writing the answer failed.
	ProtocolReplyFailed
	// ProtocolReplyUnknown means a failed third-party handler owns the reply
	// outcome and did not expose it.
	ProtocolReplyUnknown
)

// ProtocolErrorEvent describes one handled protocol decision. Callbacks run
// synchronously after that owner's existing handling and logs, without a queue
// or bookkeeping lock. Return promptly: blocking delays the owning worker.
// Calls may overlap under concurrent dispatch and with timers; there is no total
// order. A recovered callback panic is logged and does not change protocol policy.
// Calling Conn.Close is permitted; do not wait for later inbound traffic or call
// synchronous disconnect, shutdown or manager-close operations from a callback.
// Configure callbacks before use; concurrent callback replacement is unsupported.
type ProtocolErrorEvent struct {
	// Conn is the exact connection passed to the deciding handler/session.
	// Accepted connections retain their generation identity after retirement.
	// Retaining an event retains this connection object. An admitted callback
	// may finish after closure or retirement; CloseNotify is not a drain barrier.
	Conn Conn
	// Message contains copied metadata; timer events have HasHeader=false.
	Message ProtocolMessageMetadata
	// Err is the immutable classified condition, independent of logging.
	Err *ProtocolError
	// Closing records the owner's close decision, not Conn.Closed(). False
	// does not promise survival of unrelated concurrent activity.
	Closing bool
	// Reply describes the selected answer's progress at callback time.
	Reply ProtocolReplyStatus
	// ReplyCode is the selected outgoing Result-Code after existing mutation
	// hooks. Zero means no answer code is known.
	ReplyCode uint32
}

// ProtocolErrorObserver receives Server-owned protocol decisions. Server and
// ServeMux discover the first implementation through HandlerAs and Unwrap;
// an intercepting wrapper must forward deliberately. A nil HandleMessageError
// return leaves notification ownership with that handler, including asynchronous
// completion; a nonnil return leaves fallback notification to Server.
// Implementations must follow ProtocolErrorEvent's callback constraints.
// An observer may also implement ProtocolErrorEnabled() bool. False suppresses
// event construction and delivery without searching past that observer. Without
// this optional method, an observer is enabled. An intercepting wrapper that
// inherits the method must override it if its own notification policy differs.
// Discovery and enabled-state panics are recovered and logged like callback
// panics; they suppress that notification without changing protocol handling.
type ProtocolErrorObserver interface {
	// HandleProtocolError observes a handled condition without changing the
	// library's answer, logging or connection-close policy.
	HandleProtocolError(ProtocolErrorEvent)
}

func protocolMessageMetadata(m *Message) ProtocolMessageMetadata {
	if m == nil {
		return ProtocolMessageMetadata{}
	}
	metadata := ProtocolMessageMetadata{Stream: m.MessageStream()}
	if m.Header != nil {
		metadata.Header = *m.Header
		metadata.HasHeader = true
	}
	return metadata
}

// protocolObserverFor resolves only when a protocol decision needs delivery.
// found preserves first-observer ownership even when that observer is disabled.
func protocolObserverFor(c Conn, handler Handler, message *Message) (observer ProtocolErrorObserver, found bool) {
	defer func() {
		if value := recover(); value != nil {
			observer, found = nil, true
			// Resolve the logger only on panic: disabled observers do no
			// event preparation or connection-logger construction.
			observe.LogPanic(c.Logger(), value)
		}
	}()
	observer, found = HandlerAs[ProtocolErrorObserver](handler)
	if !found {
		return nil, false
	}
	if enabled, ok := observer.(interface{ ProtocolErrorEnabled() bool }); ok && !enabled.ProtocolErrorEnabled() {
		return nil, true
	}
	if mux, ok := observer.(*ServeMux); ok {
		return mux.protocolObserver(c, message), true
	}
	return observer, true
}

func (c *conn) readProtocolObserver(message *Message) ProtocolErrorObserver {
	observer, _ := protocolObserverFor(c.writer, c.dispatchHandler(), message)
	return observer
}

func (c *conn) notifyReadProtocolError(observer ProtocolErrorObserver, metadata ProtocolMessageMetadata, resultCode uint32, reply ProtocolReplyStatus) {
	if observer != nil {
		event := ProtocolErrorEvent{
			Conn: c.writer, Message: metadata, Err: NewProtocolError(ProtocolMalformedMessage, resultCode),
			Closing: true, Reply: reply,
		}
		observe.Call(c.writer.Logger(), func() { observer.HandleProtocolError(event) })
	}
}
