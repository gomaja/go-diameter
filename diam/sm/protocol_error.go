package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/observe"
)

// ProtocolErrorEnabled reports whether OnProtocolError is configured. Server
// uses this optional observer method to skip event construction for a nil hook.
// Configure Settings before use; concurrent callback replacement is unsupported.
func (sm *StateMachine) ProtocolErrorEnabled() bool {
	return sm.cfg.OnProtocolError != nil
}

// HandleProtocolError observes a Server-owned protocol decision (RFC 6733 §7).
// Server discovers it through HandlerAs; it never takes message responsibility.
func (sm *StateMachine) HandleProtocolError(event diam.ProtocolErrorEvent) {
	if hook := sm.cfg.OnProtocolError; hook != nil {
		observe.Call(event.Conn.Logger(), func() { hook(event) })
	}
}

func (sm *StateMachine) protocolError(c diam.Conn, m *diam.Message, kind diam.ProtocolErrorKind, code uint32, closing bool, reply diam.ProtocolReplyStatus, replyCode uint32) {
	if sm.cfg.OnProtocolError == nil {
		return
	}
	event := diam.ProtocolErrorEvent{Conn: c, Err: diam.NewProtocolError(kind, code), Closing: closing, Reply: reply, ReplyCode: replyCode}
	if m != nil && m.Header != nil {
		event.Message = diam.ProtocolMessageMetadata{Header: *m.Header, HasHeader: true, Stream: m.MessageStream()}
	}
	sm.HandleProtocolError(event)
}

func protocolAnswerCode(m *diam.Message) uint32 {
	if m == nil {
		return 0
	}
	for _, a := range m.AVP {
		if a != nil && a.Code == avp.ResultCode && a.VendorID == 0 {
			if v, ok := a.Data.(datatype.Unsigned32); ok {
				return uint32(v)
			}
			return 0
		}
	}
	return 0
}
