package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestAcceptedNilConnectionContext(t *testing.T) {
	d := newSMTestDictionary(creditcontrol.Dictionary())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	c := newHandshakeConn()
	//lint:ignore SA1012 Exercise a custom Conn that supplies a nil context.
	c.SetContext(nil) //nolint:staticcheck // Exercise a custom Conn that supplies a nil context.
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("accepted publish panic: %v", p)
		}
	}()
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	if _, ok := smpeer.FromContext(c.Context()); !ok {
		t.Fatal("metadata missing")
	}
	if len(c.writes) != 1 || c.Closed() {
		t.Fatalf("nil context admission writes=%d closed=%t", len(c.writes), c.Closed())
	}
	t.Logf("nil custom context accepted: writes=%d closed=%t", len(c.writes), c.Closed())
}
