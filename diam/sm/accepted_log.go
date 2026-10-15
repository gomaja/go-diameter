package sm

import (
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func (s *acceptedHandshake) record(in protocol.Input, n protocol.Notification) {
	m := in.Message
	level := slog.LevelWarn
	text := ""
	switch n.Protocol {
	case diam.ProtocolHandshakeState:
		if n.Diagnostic == "late-cer" {
			text = "sm: CER after handshake timeout; closing connection"
		} else {
			text = "sm: message before CER; closing connection"
		}
	case diam.ProtocolHandshakeTimeout:
		text = "sm: handshake timeout; closing connection"
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
		if s.sm.watchdog != nil {
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
	if text != "" {
		err := n.CauseError
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
