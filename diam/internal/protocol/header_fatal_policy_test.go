package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// RFC 6733 §§3 and 7.1.3 distinguish framing loss from an invalid base
// command header. Replacing a diagnosis preserves the decoder's fatality;
// reader ownership independently determines transport closure.
func TestHeaderValidationPreservesFatalityAndClosureOwnership(t *testing.T) {
	descriptions := []struct {
		name                   string
		code                   uint32
		fatal, framing, failed bool
	}{
		{"missing", diam.MissingAVP, false, false, false},
		{"fatal-missing", diam.MissingAVP, true, false, false},
		{"fatal-protocol", diam.CommandUnsupported, true, false, false},
		{"fatal-invalid-value", diam.InvalidAVPValue, true, false, false},
		{"fatal-avp-length", diam.InvalidAVPLength, true, false, false},
		{"fatal-failed-avp-length", diam.InvalidAVPLength, true, false, true},
		{"fatal-version", diam.UnsupportedVersion, true, true, false},
		{"fatal-message-length", diam.InvalidMessageLength, true, true, false},
	}
	for _, reader := range []bool{false, true} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, req := range []bool{false, true} {
				for _, description := range descriptions {
					name := fmt.Sprintf("reader=%t/command=%d/request=%t/%s", reader, command, req, description.name)
					t.Run(name, func(t *testing.T) {
						c := opened(t, func(cfg *Config) {
							cfg.ReaderOwnsMessageErrorClosure = reader
							cfg.CloseCEROnInvalidHeaderBitsOnly = reader
						})
						msg := request(t, command)
						if !req {
							msg = msg.Answer(diam.Success)
						}
						msg.Header.ApplicationID = 4
						input := receive(msg)
						input.ErrorInput = true
						input.Error = &diam.MessageError{ResultCode: description.code, Fatal: description.fatal}
						if description.failed {
							input.Error.FailedAVP = diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2})
						}
						effects := c.Handle(input)
						var sends int
						for _, effect := range effects {
							if effect.Kind != Send {
								continue
							}
							sends++
							if !req {
								t.Fatal("malformed answer selected an answer")
							}
							if effect.Message.Header.CommandCode != command || effect.Message.Header.HopByHopID != msg.Header.HopByHopID || effect.Message.Header.EndToEndID != msg.Header.EndToEndID {
								t.Fatalf("header rejection changed exchange coordinates: %+v", effect.Message.Header)
							}
							completion := complete(effect)
							completion.ReplyCode = resultCode(t, effect.Message)
							effects = append(effects, c.Handle(completion)...)
						}
						if req && sends != 1 {
							t.Fatalf("request selected %d answers, want one", sends)
						}
						wantClosing := description.fatal || req && command == diam.CapabilitiesExchange
						wantCode := uint32(diam.InvalidHDRBits)
						wantKind := diam.ProtocolInvalidHeader
						if description.framing {
							wantCode = description.code
							wantKind = diam.ProtocolMalformedMessage
						}
						notice := find(t, effects, Notify).Notification
						wantReply, wantReplyCode := diam.ProtocolReplyNone, uint32(0)
						if req {
							wantReply, wantReplyCode = diam.ProtocolReplyWritten, wantCode
						}
						if notice.Reply != wantReply || notice.ReplyCode != wantReplyCode {
							t.Fatalf("header rejection reply=%v/%d, want %v/%d", notice.Reply, notice.ReplyCode, wantReply, wantReplyCode)
						}
						if notice.Protocol != wantKind || notice.ResultCode != wantCode || notice.Closing != wantClosing {
							t.Fatalf("header/error precedence notification=%+v, want %s/%d closing=%t", notice, wantKind, wantCode, wantClosing)
						}
						wantClosed := wantClosing
						if reader {
							wantClosed = req && command == diam.CapabilitiesExchange && !description.framing
						}
						if got := c.Snapshot().Phase(); (got == Closed) != wantClosed {
							t.Fatalf("phase=%v, want closed=%t", got, wantClosed)
						}
					})
				}
			}
		}
	}
}
