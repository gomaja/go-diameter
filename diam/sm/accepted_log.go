package sm

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func (s *acceptedHandshake) record(in protocol.Input, n protocol.Notification) {
	if n.Diagnostic == "external-message-error" {
		return
	}
	m := in.Message
	level := slog.LevelWarn
	text := ""
	switch n.Protocol {
	case diam.ProtocolHandshakeState:
		if s.client != nil {
			text = "sm: Wait-I-CEA rejected message; closing connection"
		} else if n.Diagnostic == "late-cer" {
			text = "sm: CER after handshake timeout; closing connection"
		} else {
			text = "sm: message before CER; closing connection"
		}
	case diam.ProtocolHandshakeTimeout:
		text = "sm: handshake timeout; closing connection"
		if s.client != nil {
			text = "sm: CEA timeout; closing connection"
		}
	case diam.ProtocolDisconnectTimeout:
		text = "sm: Wait-Returns timeout; closing connection"
		if n.Diagnostic == "local-disconnect" {
			text = "sm: disconnect timeout; closing connection"
		}
	case diam.ProtocolWatchdogTimeout:
		text = "sm: watchdog timeout; closing connection"
	case diam.ProtocolInvalidHeader:
		if in.Kind == protocol.Continue {
			level = slog.LevelError
			text = "sm: pre-hook changed protocol coordinates; closing connection"
		} else {
			text = "sm: invalid message header"
			if s.client != nil && s.snapshot().Handshake().Err() != nil {
				text = "sm: CEA rejected; closing connection"
			}
		}
	case diam.ProtocolCEARejected:
		if s.client != nil {
			text = "sm: CEA rejected; closing connection"
			if in.Error != nil {
				text = "sm: Wait-I-CEA rejected message; closing connection"
			}
		}
	case diam.ProtocolInvalidRequest:
		text = "sm: invalid request"
	case diam.ProtocolUnsupportedAVP:
		text = "sm: unsupported mandatory AVP"
	case diam.ProtocolUnsupportedApplication, diam.ProtocolUnsupportedCommand:
		if n.Reply == diam.ProtocolReplyWritten {
			level = slog.LevelInfo
			text = "sm: unsupported command answered"
		}
	case diam.ProtocolCERRejected:
		text = "sm: rejected CER; closing connection"
	case diam.ProtocolInvalidDWR:
		text = "sm: invalid DWR"
	case diam.ProtocolInvalidDPR:
		text = "sm: invalid DPR"
	case diam.ProtocolInvalidDWA:
		if s.policy != nil {
			text = "sm: invalid DWA"
		} else {
			text = "sm: invalid base message"
		}
	case diam.ProtocolRejectedDWA:
		text = "sm: rejected DWA"
	case diam.ProtocolInvalidDPA:
		if n.ResultCode != 0 {
			text = "sm: invalid base message"
		} else {
			text = "sm: invalid DPA"
		}
	case diam.ProtocolUnexpectedMessage:
		if n.Diagnostic == "duplicate-cea" {
			break
		}
		if n.Diagnostic == "cea-correlation" {
			text = "sm: CEA identifiers mismatch; answer discarded"
			break
		}
		if s.client != nil && m != nil && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag == 0 && s.phase() == protocol.WaitCEA {
			text = "sm: CEA identifiers mismatch; answer discarded"
			break
		}
		if n.Diagnostic == "dpa-correlation" {
			text = "sm: DPA identifiers mismatch; answer discarded"
			break
		}
		if n.Diagnostic == "dpa-host" {
			text = "sm: DPA Origin-Host mismatch; answer discarded"
			break
		}
		if m != nil && m.Header.CommandCode == diam.DisconnectPeer {
			break
		}
		if m != nil && m.Header.CommandCode == diam.CapabilitiesExchange && m.Header.CommandFlags&diam.RequestFlag != 0 {
			text = "sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible"
		} else {
			text = "sm: unhandled answer discarded"
		}
	}
	if n.Diagnostic == "external-reject-cer" {
		text = "sm: rejected CER; closing connection"
	}
	if n.Diagnostic == "external-invalid-base" {
		text = "sm: invalid base message"
	}
	if text != "" {
		err := n.CauseError
		if n.Diagnostic == "external-reject-cer" && base.FatalHeaderError(in.Error) {
			err = in.Error
		}
		if s.client == nil {
			// Client diagnostics include the underlying validation cause.
			// Accepted DWA/DPA records expose errors only for malformed input.
			switch n.Protocol {
			case diam.ProtocolRejectedDWA:
				err = nil
			case diam.ProtocolInvalidDWA:
				var malformed *diam.MessageError
				if !errors.As(err, &malformed) {
					err = nil
				}
			case diam.ProtocolInvalidDPA:
				if n.ResultCode == 0 {
					err = nil
				}
			}
		}
		if s.client != nil {
			switch n.Protocol {
			case diam.ProtocolHandshakeTimeout:
				err = ErrHandshakeTimeout
			case diam.ProtocolHandshakeState:
				if err == nil {
					err = fmt.Errorf("non-CEA received while waiting for CEA")
				}
			case diam.ProtocolCEARejected:
				_, err = fromValidatedCEA(s.snapshot().Handshake().CEA(), nil, s.snapshot().Handshake().Err())
			case diam.ProtocolInvalidHeader:
				if cause := s.snapshot().Handshake().Err(); cause != nil {
					err = cause
				}
			}
		}
		if n.Diagnostic == "local-disconnect" {
			err = ErrDisconnectTimeout
		}
		if (err == nil || n.Protocol == diam.ProtocolInvalidRequest || n.Protocol == diam.ProtocolUnsupportedAVP) && n.ResultCode != 0 {
			err = diam.NewProtocolError(n.Protocol, n.ResultCode)
		}
		if n.Protocol == diam.ProtocolUnsupportedCommand || n.Protocol == diam.ProtocolUnsupportedApplication {
			s.conn.Logger().LogAttrs(m.Context(), level, text, slog.Any("message", m), slog.Uint64("result_code", uint64(n.ResultCode)))
		} else {
			logMessage(s.conn, m, level, text, err)
		}
	}
}
