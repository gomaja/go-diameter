package protocol

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
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
		{"decoded", 0, false, false, false},
		{"missing", diam.MissingAVP, false, false, false},
		{"fatal-missing", diam.MissingAVP, true, false, false},
		{"fatal-protocol", diam.CommandUnsupported, true, false, false},
		{"fatal-invalid-value", diam.InvalidAVPValue, true, false, false},
		{"fatal-avp-length", diam.InvalidAVPLength, true, false, false},
		{"fatal-failed-avp-length", diam.InvalidAVPLength, true, false, true},
		{"fatal-version", diam.UnsupportedVersion, true, true, false},
		{"fatal-message-length", diam.InvalidMessageLength, true, true, false},
	}
	headers := []struct {
		name  string
		flags uint8
		app   uint32
	}{
		{"application-id", 0, 4},
		{"proxiable", diam.ProxiableFlag, 0},
		{"error", diam.ErrorFlag, 0},
		{"proxiable-error", diam.ProxiableFlag | diam.ErrorFlag, 0},
	}
	owners := []struct {
		name             string
		reader, onlyBits bool
	}{
		{"core", false, false},
		{"reader", true, false},
		{"reader-invalid-header-bits", true, true},
	}
	for _, owner := range owners {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, req := range []bool{false, true} {
				for _, fixture := range []string{"responder", "externally-admitted", "initiator"} {
					for _, hooks := range []bool{false, true} {
						for _, header := range headers {
							// CER requests exercise every frontend configuration. Other
							// base commands supply header/fatality controls.
							if (command != diam.CapabilitiesExchange || !req) && (fixture != "responder" || hooks || header.name != "application-id" || owner.name == "reader") {
								continue
							}
							for _, description := range descriptions {
								name := fmt.Sprintf("%s/%s/hooks=%t/command=%d/request=%t/%s/%s", fixture, owner.name, hooks, command, req, header.name, description.name)
								t.Run(name, func(t *testing.T) {
									configure := func(cfg *Config) {
										cfg.ReaderOwnsMessageErrorClosure = owner.reader
										cfg.CloseCEROnInvalidHeaderBitsOnly = owner.onlyBits
										cfg.Watchdog = command == diam.CapabilitiesExchange && req
										cfg.WatchdogInterval = 6 * time.Second
									}
									var c *Core
									switch fixture {
									case "externally-admitted":
										cfg := configuration(t)
										configure(&cfg)
										var err error
										c, err = NewAdmitted(cfg, PeerClaims{Host: "remote.example", Realm: "example", RemoteApplications: []uint32{4}, CER: true})
										if err != nil {
											t.Fatal(err)
										}
									case "initiator":
										c = machine(t, configure, func(cfg *Config) { cfg.Role = Initiator })
										sent := grant(t, c, c.Handle(event(Start)))
										c.Handle(complete(sent))
										answer, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
										if err != nil {
											t.Fatal(err)
										}
										ready := find(t, c.Handle(receive(answer)), HandshakeReady)
										release := event(ReleaseAdmission)
										release.Token = ready.Token
										c.Handle(release)
									default:
										c = opened(t, configure)
									}
									c.cfg.Hooks = hooks
									if c.cfg.Watchdog {
										probe(t, c)
										tick(t, c)
									}
									health := c.Snapshot().Watchdog()
									msg := request(t, command)
									if !req {
										msg = msg.Answer(diam.Success)
									}
									msg.Header.ApplicationID = header.app
									msg.Header.CommandFlags |= header.flags
									input := receive(msg)
									input.At = epoch.Add(13 * time.Second)
									if description.code != 0 {
										input.ErrorInput = true
										input.Error = &diam.MessageError{ResultCode: description.code, Fatal: description.fatal}
										if description.failed {
											input.Error.FailedAVP = diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2})
										}
									}
									wantClosing := description.fatal || req && command == diam.CapabilitiesExchange
									wantCode := uint32(diam.InvalidHDRBits)
									wantKind := diam.ProtocolInvalidHeader
									if description.framing {
										wantCode = description.code
										wantKind = diam.ProtocolMalformedMessage
									}
									external := owner.reader || fixture == "externally-admitted" && input.ErrorInput
									wantClosed := wantClosing
									if external {
										wantClosed = req && command == diam.CapabilitiesExchange && (!owner.onlyBits || !description.framing)
										wantClosing = description.fatal || wantClosed
									}
									effects := c.Handle(input)
									if c.Snapshot().Watchdog() != health {
										t.Fatalf("invalid header earned validity credit: before=%+v after=%+v", health, c.Snapshot().Watchdog())
									}
									var sends int
									for _, effect := range effects {
										if effect.Kind == RunHook {
											t.Fatal("invalid header reached the hook")
										}
										if effect.Kind != Send {
											continue
										}
										sends++
										if !req {
											t.Fatal("malformed answer selected an answer")
										}
										wantFlags := uint8(0)
										if wantCode >= 3000 && wantCode < 4000 {
											wantFlags = diam.ErrorFlag | msg.Header.CommandFlags&diam.ProxiableFlag
										}
										if !effect.Required || effect.CloseAfter != wantClosed || resultCode(t, effect.Message) != wantCode || effect.Message.Header.CommandFlags != wantFlags {
											t.Fatalf("header rejection send=%+v header=%+v, want required answer %d flags=%#x close-after=%t", effect, effect.Message.Header, wantCode, wantFlags, wantClosed)
										}
										if effect.Message.Header.CommandCode != command || effect.Message.Header.ApplicationID != 0 || effect.Message.Header.HopByHopID != msg.Header.HopByHopID || effect.Message.Header.EndToEndID != msg.Header.EndToEndID {
											t.Fatalf("header rejection changed exchange coordinates: %+v", effect.Message.Header)
										}
										completion := complete(effect)
										completion.ReplyCode = resultCode(t, effect.Message)
										effects = append(effects, c.Handle(completion)...)
									}
									if req && sends != 1 {
										t.Fatalf("request selected %d answers, want one", sends)
									}
									notice := find(t, effects, Notify).Notification
									wantReply, wantReplyCode := diam.ProtocolReplyNone, uint32(0)
									if req {
										wantReply, wantReplyCode = diam.ProtocolReplyWritten, wantCode
									}
									wantDiagnostic := ""
									if external {
										wantDiagnostic = "external-message-error"
										if wantClosed {
											wantDiagnostic = "external-reject-cer"
										}
									} else if req && command == diam.CapabilitiesExchange {
										wantDiagnostic = "reject-cer"
									}
									if notice.Kind != ProtocolNotice || notice.Reply != wantReply || notice.ReplyCode != wantReplyCode || notice.Protocol != wantKind || notice.ResultCode != wantCode || notice.Closing != wantClosing || notice.Diagnostic != wantDiagnostic {
										t.Fatalf("header/error precedence notification=%+v, want %s/%d closing=%t reply=%v/%d diagnostic=%q", notice, wantKind, wantCode, wantClosing, wantReply, wantReplyCode, wantDiagnostic)
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
		}
	}
}
