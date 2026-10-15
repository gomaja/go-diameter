package sm

import (
	"io"

	"github.com/gomaja/go-diameter/diam"
)

// writeRequiredReply checks completion even for custom Conns whose writer
// returns a short count without an error. A partial answer requires closure.
func writeRequiredReply(c diam.Conn, answer *diam.Message) error {
	n, err := answer.WriteTo(c)
	if err == nil && n != int64(answer.Len()) {
		err = io.ErrShortWrite
	}
	return err
}

// closeRequiredReply prevents further admission and probe publication before
// closing. A required reply failure is terminal throughout its generation.
func (sm *StateMachine) closeRequiredReply(c diam.Conn) {
	state := sm.enterClosing(c)
	state.replyClose.Do(func() {
		if !c.Closed() {
			c.Close()
		}
	})
}

func (sm *StateMachine) requiredReplyFailed(c diam.Conn, request *diam.Message, code uint32) {
	sm.closeRequiredReply(c)
	sm.protocolError(c, request, diam.ProtocolReplyFailure, 0, true, diam.ProtocolReplyFailed, code)
}
