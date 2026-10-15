package protocol

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// HandshakeResult preserves semantic CEA processing separately from protocol
// observer metadata (RFC 6733 §§5.3.2,7). Adapters translate base parser error
// identities into their public error types without parsing the message again.
// A rejected or partially parsed CEA never becomes negotiated capabilities.
type HandshakeResult struct {
	err error
	cea *base.CEA
}

func newHandshakeResult(err error, cea *base.CEA) HandshakeResult {
	return HandshakeResult{err: copyHandshakeError(err), cea: copyCEA(cea)}
}

func (r HandshakeResult) Err() error     { return copyHandshakeError(r.err) }
func (r HandshakeResult) CEA() *base.CEA { return copyCEA(r.cea) }

// Parser errors with mutable evidence are copied on capture and access. Plain
// sentinels retain identity; wrapped errors retain errors.Is/errors.As behavior.
func copyHandshakeError(err error) error {
	switch e := err.(type) {
	case *base.ErrFailedResultCode:
		return &base.ErrFailedResultCode{CEA: copyCEA(e.CEA)}
	case *base.ErrUnexpectedAVP:
		return &base.ErrUnexpectedAVP{AVP: base.CloneAVP(e.AVP)}
	case *diam.MessageError:
		out := *e
		out.FailedAVP = base.CloneAVP(e.FailedAVP)
		out.Err = copyHandshakeError(e.Err)
		return &out
	case *diam.ValidationError:
		out := *e
		out.FailedAVP = base.CloneAVP(e.FailedAVP)
		return &out
	case interface{ Unwrap() error }:
		return handshakeError{message: err.Error(), cause: copyHandshakeError(e.Unwrap())}
	default:
		return err
	}
}

type handshakeError struct {
	message string
	cause   error
}

func (e handshakeError) Error() string { return e.message }
func (e handshakeError) Unwrap() error { return e.cause }
