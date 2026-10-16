package peer

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

// A direct fatal body-error callback reports its required answer without
// assuming the reader's responsibility for closing the transport.
func TestManagerFatalRepeatedCERRequiresErrorAnswer(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("dialed=%t", dialed), func(t *testing.T) {
			p := newCoreActivityWire(t, dialed)
			request := capabilitiesExchangeRequest(t)
			description := &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			if err := p.m.HandleMessageError(p.s.c, request, description); err != nil {
				t.Fatal(err)
			}
			event := protocolErrorReceive(t, p.events)
			protocolErrorCheck(t, event, p.s.c, *request.Header, diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, diam.ProtocolReplyQueued, diam.InvalidAVPLength)
			answer := read(t, p.c)
			if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || code(t, answer) != diam.InvalidAVPLength {
				t.Fatalf("fatal repeated CER error answer changed: %+v", answer)
			}
			if err := answer.ValidateOutgoing(); err != nil {
				t.Fatalf("fatal repeated CER answer grammar: %v", err)
			}
			probe := watchdogRequest(t)
			write(t, p.c, probe)
			if next := read(t, p.c); next.Header.CommandCode != diam.DeviceWatchdog || next.Header.HopByHopID != probe.Header.HopByHopID || code(t, next) != diam.Success {
				t.Fatalf("fatal callback changed transport ownership: %+v", next)
			}
			select {
			case extra := <-p.events:
				t.Fatalf("duplicate fatal repeated CER report: %+v", extra)
			default:
			}
		})
	}
}
