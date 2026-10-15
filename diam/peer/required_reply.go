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

func (s *session) sendRequired(answer, request *diam.Message, closeAfter bool, code uint32, delivery ...*protocolDelivery) error {
	w := writeRequest{msg: answer, closeAfter: closeAfter, required: true}
	if s.m.ProtocolErrorEnabled() {
		w.reply = requiredReplyEvent(s.c, request, code)
		if len(delivery) != 0 {
			w.replyDelivery = delivery[0]
		}
	}
	return s.sendWrite(w)
}

// Calls outside actor admission still report their queue decision before a
// concurrent writer reports failure. The actor's delivery keeps its existing
// boundary after Server admission is released, so observers can close Conn.
func (m *Manager) requiredReplyDelivery(delivery []*protocolDelivery) ([]*protocolDelivery, func()) {
	if !m.ProtocolErrorEnabled() || len(delivery) != 0 && delivery[0] != nil {
		return delivery, func() {}
	}
	d := newProtocolDelivery()
	return []*protocolDelivery{d}, func() { d.deliver(m) }
}

func (a *actor) requiredReplyFailed(s *session, request *diam.Message, code uint32) {
	s.close()
	a.protocolError(s.c, request, diam.ProtocolReplyFailure, 0, true, diam.ProtocolReplyFailed, code)
}
