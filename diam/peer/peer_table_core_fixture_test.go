package peer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// A newly accepted transport has a started responder core but no CER candidate.
// Candidate parsing and election remain production Receive effects.
func peerTableResponder(t *testing.T, s *session) {
	t.Helper()
	if err := s.initProtocol(); err != nil {
		t.Fatal(err)
	}
	s.runProtocol(protocol.Input{Kind: protocol.Start}, s.takeStartup(), nil)
}
