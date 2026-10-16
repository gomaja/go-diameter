package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

// Manager retains the required fatal-error answer while leaving transport
// closure to the decoder's caller. StateMachine has its own repeat policy.
func TestRepeatedCERFatalDecoderDisposition(t *testing.T) {
	for _, manager := range []bool{false, true} {
		for _, errorInput := range []bool{false, true} {
			for _, fatal := range []bool{false, true} {
				t.Run(fmt.Sprintf("manager=%t/error-input=%t/fatal=%t", manager, errorInput, fatal), func(t *testing.T) {
					c := opened(t, func(cfg *Config) {
						cfg.RejectFatalRepeatedCER = manager
						cfg.ReaderOwnsMessageErrorClosure = manager
						cfg.QueueWrites = true
					})
					input := receive(cer(t))
					input.ErrorInput = errorInput
					input.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: fatal}
					effects := c.Handle(input)
					if !manager || !fatal {
						notice := find(t, effects, Notify).Notification
						if notice.Protocol != diam.ProtocolUnexpectedMessage || notice.ResultCode != 0 || notice.Closing || notice.Reply != diam.ProtocolReplyNone || c.Snapshot().Phase() != Open {
							t.Fatalf("recoverable/frontend repeated CER disposition changed: %+v phase=%v", notice, c.Snapshot().Phase())
						}
						for _, effect := range effects {
							if effect.Kind == Send || effect.Kind == Close {
								t.Fatalf("ignored repeated CER selected terminal work: %+v", effect)
							}
						}
						return
					}
					sent := find(t, effects, Send)
					if !sent.Required || sent.CloseAfter || resultCode(t, sent.Message) != diam.InvalidAVPLength || sent.Message.Header.CommandCode != diam.CapabilitiesExchange || sent.Message.Header.HopByHopID != input.Message.Header.HopByHopID || sent.Message.Header.EndToEndID != input.Message.Header.EndToEndID {
						t.Fatalf("fatal repeated CER required answer changed: %+v", sent)
					}
					queued := event(WriteResult)
					queued.Token = sent.Token
					queued.Stage = QueueStage
					queued.ReplyCode = diam.InvalidAVPLength
					notice := find(t, c.Handle(queued), Notify).Notification
					if notice.Protocol != diam.ProtocolMalformedMessage || notice.ResultCode != diam.InvalidAVPLength || !notice.Closing || notice.Reply != diam.ProtocolReplyQueued || notice.ReplyCode != diam.InvalidAVPLength {
						t.Fatalf("fatal repeated CER queue report changed: %+v", notice)
					}
					if c.Snapshot().Phase() != Open {
						t.Fatal("fatal repeated CER closed before its required write")
					}
					written := complete(sent)
					written.ReplyCode = diam.InvalidAVPLength
					effects = c.Handle(written)
					if c.Snapshot().Phase() != Open {
						t.Fatal("fatal callback took transport closure from its caller")
					}
					for _, effect := range effects {
						if effect.Kind == Notify || effect.Kind == Close {
							t.Fatalf("successful reply duplicated its report or closed the transport: %+v", effect)
						}
					}
				})
			}
		}
	}
}
