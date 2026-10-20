//go:build linux && !386

package peer_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestManagerAcceptedSCTPInvalidOpenCERAnswerBeforeEOF(t *testing.T) {
	frontend := parityFrontends[2]
	h := fatalMessageManagerTransport(t, frontend, "sctp")
	request := contractBase(h.dict, diam.CapabilitiesExchange, true)
	request.Header.CommandFlags |= diam.ProxiableFlag
	request.Header.HopByHopID, request.Header.EndToEndID = 0x55667788, 0x12345678
	h.write(t, request)
	answer := h.read(t)
	if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags != diam.ErrorFlag|diam.ProxiableFlag || answer.Header.ApplicationID != 0 || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || contractCode(t, answer) != diam.InvalidHDRBits {
		t.Fatalf("invalid Open CER answer=%v", answer)
	}
	for _, field := range []struct {
		code uint32
		want datatype.DiameterIdentity
	}{{avp.OriginHost, "local.example.net"}, {avp.OriginRealm, "example.net"}} {
		if value := contractField(t, answer, field.code).Data; value != field.want {
			t.Fatalf("answer AVP %d=%v, want %v", field.code, value, field.want)
		}
	}
	h.eof(t)
}
