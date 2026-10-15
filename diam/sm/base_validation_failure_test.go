package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func TestBaseValidationUnsupportedApplicationReplyFailure(t *testing.T) {
	p := newProtocolLocalWire(t, func(c *Settings, _ *protocolLocalFaults) {
		c.ValidateRequests = true
	}, true)
	p.faults.write.Store(true)
	request := diam.NewMessage(999, diam.RequestFlag|diam.ProxiableFlag, 0xabcdef, 1, 2, p.conn.Dictionary())
	header := p.send(t, request)
	e := protocolEvent(t, p.events)
	assertProtocolEvent(t, e, p.conn, &header, diam.ProtocolUnsupportedApplication, diam.ApplicationUnsupported, true, diam.ProtocolReplyFailed, diam.ApplicationUnsupported)
	if !p.conn.Closed() {
		t.Fatal("failed unsupported-application reply left the connection open")
	}
}
