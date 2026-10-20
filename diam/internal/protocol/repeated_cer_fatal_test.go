package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

// Fatal repeated CERs require an error answer; reader ownership determines
// whether the core also closes after the answer completes.
func TestRepeatedCERFatalDecoderDisposition(t *testing.T) {
	headers := []struct {
		name  string
		flags uint8
	}{
		{"plain", 0},
		{"retransmitted", diam.RetransmittedFlag},
		{"reserved", 0x0f},
	}
	bodies := []struct {
		name           string
		decoder, fatal bool
		invalid        bool
	}{
		{"decoded", false, false, false},
		{"invalid-body", false, false, true},
		{"recoverable-error", true, false, false},
		{"fatal-error", true, true, false},
	}
	for _, reader := range []bool{false, true} {
		for _, errorInput := range []bool{false, true} {
			for _, hooks := range []bool{false, true} {
				for _, header := range headers {
					for _, body := range bodies {
						name := fmt.Sprintf("reader=%t/error-input=%t/hooks=%t/%s/%s", reader, errorInput, hooks, header.name, body.name)
						t.Run(name, func(t *testing.T) {
							c := opened(t, func(cfg *Config) {
								cfg.ReaderOwnsMessageErrorClosure = reader
								cfg.QueueWrites = true
							})
							c.cfg.Hooks = hooks
							input := receive(cer(t))
							input.Message.Header.CommandFlags |= header.flags
							input.ErrorInput = errorInput
							if body.decoder {
								input.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: body.fatal}
							}
							if body.invalid {
								input.Message.AVP = nil
							}
							effects := c.Handle(input)
							if !body.fatal {
								if hooks && !body.decoder && !errorInput {
									wantKinds(t, effects, RunHook)
									hook := find(t, effects, RunHook)
									continuation := event(Continue)
									continuation.Token, continuation.Message = hook.Token, hook.Message
									effects = c.Handle(continuation)
								}
								wantKinds(t, effects, Discard, Notify)
								notice := find(t, effects, Notify).Notification
								if notice.Protocol != diam.ProtocolUnexpectedMessage || notice.ResultCode != 0 || notice.Closing || notice.Reply != diam.ProtocolReplyNone || c.Snapshot().Phase() != Open {
									t.Fatalf("recoverable repeated CER disposition changed: %+v phase=%v", notice, c.Snapshot().Phase())
								}
								return
							}
							for _, effect := range effects {
								if effect.Kind == RunHook {
									t.Fatal("fatal repeated CER reached the hook")
								}
							}
							sent := find(t, effects, Send)
							if !sent.Required || sent.CloseAfter == reader || resultCode(t, sent.Message) != diam.InvalidAVPLength || sent.Message.Header.CommandCode != diam.CapabilitiesExchange || sent.Message.Header.HopByHopID != input.Message.Header.HopByHopID || sent.Message.Header.EndToEndID != input.Message.Header.EndToEndID {
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
							if (c.Snapshot().Phase() == Closed) == reader {
								t.Fatalf("fatal repeated CER closure ownership changed: reader=%t phase=%v", reader, c.Snapshot().Phase())
							}
							for _, effect := range effects {
								if effect.Kind == Notify || reader && effect.Kind == Close {
									t.Fatalf("successful reply duplicated its report or closed the transport: %+v", effect)
								}
							}
						})
					}
				}
			}
		}
	}
}
