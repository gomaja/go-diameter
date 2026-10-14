package peer

import (
	"errors"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/observe"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// ProtocolErrorEnabled reports whether Settings.OnProtocolError is configured.
// Server uses this optional observer method to skip event construction for a nil
// hook. Configure Settings before use; concurrent replacement is unsupported.
func (m *Manager) ProtocolErrorEnabled() bool {
	return m.cfg.Settings.OnProtocolError != nil
}

// HandleProtocolError delivers Server-owned decisions through the same hook as
// decisions made by Manager. It does not use the bounded OnPeerEvent queue.
func (m *Manager) HandleProtocolError(event diam.ProtocolErrorEvent) {
	if callback := m.cfg.Settings.OnProtocolError; callback != nil {
		logger := m.logger()
		if event.Conn != nil {
			logger = event.Conn.Logger()
		}
		observe.Call(logger, func() { callback(event) })
	}
}

func (m *Manager) protocolError(c diam.Conn, message *diam.Message, kind diam.ProtocolErrorKind, result uint32, closing bool, reply diam.ProtocolReplyStatus, replyCode uint32) {
	if m.cfg.Settings.OnProtocolError == nil {
		return
	}
	event := diam.ProtocolErrorEvent{Conn: c, Err: diam.NewProtocolError(kind, result), Closing: closing, Reply: reply, ReplyCode: replyCode}
	if message != nil {
		event.Message.Stream = message.MessageStream()
		if message.Header != nil {
			event.Message.Header = *message.Header
			event.Message.HasHeader = true
		}
	}
	m.HandleProtocolError(event)
}

func protocolResultCode(err error) uint32 {
	var messageError *diam.MessageError
	if errors.As(err, &messageError) {
		return messageError.ResultCode
	}
	var failed *smparser.ErrFailedResultCode
	if errors.As(err, &failed) {
		return failed.ResultCode
	}
	var dwaError *dwaResultCodeError
	if errors.As(err, &dwaError) {
		return dwaError.result
	}
	return 0
}

var _ diam.ProtocolErrorObserver = (*Manager)(nil)
