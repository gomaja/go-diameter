package peer

import "github.com/gomaja/go-diameter/diam"

// requiredReplyEvent snapshots request metadata before a queued answer may
// outlive its receive callback. Completion notifications never retain its AVPs.
func requiredReplyEvent(c diam.Conn, request *diam.Message, code uint32) *diam.ProtocolErrorEvent {
	e := &diam.ProtocolErrorEvent{Conn: c, Err: diam.NewProtocolError(diam.ProtocolReplyFailure, 0),
		Closing: true, Reply: diam.ProtocolReplyFailed, ReplyCode: code}
	if request != nil {
		e.Message.Stream = request.MessageStream()
		if request.Header != nil {
			e.Message.Header = *request.Header
			e.Message.HasHeader = true
		}
	}
	return e
}
