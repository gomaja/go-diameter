package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// Client's connection-local handshake handlers must leave a shared server's
// CER registration intact (RFC 6733 §5.3), including across repeated dials.
func TestClientDialsPreserveSharedInboundCER(t *testing.T) {
	shared := mustNewStateMachine(t, serverSettings)
	inbound := diamtest.NewServer(shared, dict.Default)
	defer inbound.Close()
	remote := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer remote.Close()
	client := newLivenessClient(t)
	client.Handler = shared
	client.EnableWatchdog = false
	client.RetransmitInterval = 2 * time.Second
	for i := 0; i < 2; i++ {
		c, err := client.Dial(remote.Addr)
		if err != nil {
			t.Fatalf("dial%d: %v", i, err)
		}
		c.Close()
	}
	peer := newLivenessClient(t)
	peer.EnableWatchdog = false
	peer.RetransmitInterval = 2 * time.Second
	c, err := peer.Dial(inbound.Addr)
	if err != nil {
		t.Fatalf("inbound CER after repeated Dial: %v", err)
	}
	defer c.Close()
	var _ diam.Handler = shared
}
