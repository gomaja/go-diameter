package peer

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func (m *Manager) rejectBaseMessage(s *session, msg *diam.Message, err *diam.MessageError, initial, closing bool, delivery ...*protocolDelivery) {
	m.report(s, msg, err)
	kind := diam.ProtocolInvalidRequest
	if base.ValidateHeader(msg) != nil {
		kind = diam.ProtocolInvalidHeader
	}
	if msg.Header.CommandFlags&diam.RequestFlag == 0 {
		if kind != diam.ProtocolInvalidHeader {
			kind = base.AnswerErrorKind(msg)
		}
		m.protocolError(s.c, msg, kind, err.ResultCode, false, diam.ProtocolReplyNone, 0, delivery...)
		return
	}
	rejection := &base.RequestError{Kind: kind, Code: err.ResultCode}
	if err.FailedAVP != nil {
		rejection.Failed = []*diam.AVP{err.FailedAVP}
	}
	m.rejectRequest(s, msg, rejection, initial, closing, delivery...)
}

func (m *Manager) rejectRequest(s *session, msg *diam.Message, rejection *base.RequestError, initial, closing bool, delivery ...*protocolDelivery) {
	if closing {
		m.protocolError(s.c, msg, rejection.Kind, rejection.Code, false, diam.ProtocolReplyNone, 0, delivery...)
		return
	}
	if initial {
		s.terminal.Store(true)
	}
	answer, err := base.BuildErrorAnswer(msg, m.baseSettings(s.c), rejection.Code, rejection.Failed, rejection.Code >= 3000 && rejection.Code < 4000)
	if err == nil {
		err = s.send(answer, initial)
	}
	m.reportLocal(s, msg, "peer: request rejection answer failed", err)
	reply := diam.ProtocolReplyQueued
	if err != nil {
		reply = diam.ProtocolReplyFailed
		if initial {
			s.close()
		}
	}
	m.protocolError(s.c, msg, rejection.Kind, rejection.Code, initial, reply, rejection.Code, delivery...)
}
