package sm

import (
	"context"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestApplicationCallbackRequiresPublicPeerContext(t *testing.T) {
	cfg := testMessageErrorSettings()
	cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
	sm := mustNewStateMachine(t, cfg)
	c := newAcceptedWatchdogProbeConn()
	defer close(c.done)
	called := false
	sm.HandleFunc("ALL", func(diam.Conn, *diam.Message) { called = true })
	sm.ServeDIAM(c, regressionCER(t, c.Dictionary(), 1001))
	state := sm.acceptedCore(c, nil, false)
	if state == nil || !state.readyOpen() {
		t.Fatal("capability exchange did not admit the peer")
	}

	// Replacing the public metadata does not revoke the core's bound identity.
	// Application callbacks retain their independent context admission gate.
	c.SetContext(context.Background())
	sm.ServeDIAM(c, diam.NewMessage(0xeeff, diam.RequestFlag, 1001, 31, 32, c.Dictionary()))
	if called || !c.Closed() || state.phase() != protocol.Open {
		t.Fatalf("context admission: callback=%t closed=%t core phase=%v", called, c.Closed(), state.phase())
	}
}
