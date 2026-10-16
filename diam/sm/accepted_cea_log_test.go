package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

// RFC 6733 §§5.3 and 7.2: an answer is discarded without generating an answer.
func TestAcceptedMalformedCEALogCompatibilityWire(t *testing.T) {
	p := newProtocolWire(t, nil, true)
	m := diam.NewMessage(diam.CapabilitiesExchange, 0, 0, 17, 18, p.conn.Dictionary())
	h := p.send(t, m)
	e := protocolEvent(t, p.events)
	assertProtocolEvent(t, e, p.conn, &h, diam.ProtocolCEARejected, diam.MissingAVP, false, diam.ProtocolReplyNone, 0)
	p.usable(t)
	logs := p.logs.Records()
	t.Logf("accepted malformed CEA: event=%+v logs=%v closed=%t", e, logs, p.conn.Closed())
	if len(logs) != 0 {
		t.Fatalf("accepted malformed CEA acquired %d log records", len(logs))
	}
}
