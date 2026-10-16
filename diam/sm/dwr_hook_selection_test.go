package sm

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// The receipt goroutine must finish without consulting OnDWR while admission
// belongs to OnHandshake. Joining it before returning then orders installation
// before the held hook executes (https://go.dev/ref/mem#chan).
func concurrentDWRHookInstallation(t *testing.T, sm *StateMachine, request *diam.Message, calls *atomic.Int32) func(diam.Conn, *smpeer.Metadata) {
	t.Helper()
	return func(c diam.Conn, _ *smpeer.Metadata) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			sm.ServeDIAM(c, request)
		}()
		sm.Settings().OnDWR = func(diam.Conn, *diam.Message) { calls.Add(1) }
		<-done
		if calls.Load() != 0 {
			t.Error("held DWR ran its hook before OnHandshake returned")
		}
	}
}

func TestConcurrentHeldDWRUsesHookInstalledByHandshake(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		d := newSMTestDictionary(dict.Base())
		cfg := testMessageErrorSettings(d)
		cfg.HandshakeTimeout = -1
		sm := mustNewStateMachine(t, cfg, d)
		c := newHandshakeConn()
		request := regressionDWR(t)
		var calls atomic.Int32
		cfg.OnHandshake = concurrentDWRHookInstallation(t, sm, request, &calls)
		sm.ServeDIAM(c, regressionCER(t, d, 1001))
		s := sm.acceptedCore(c, nil, false)
		defer s.apply(protocol.Input{Kind: protocol.Abort})
		if calls.Load() != 1 || len(c.writes) != 2 {
			t.Fatalf("DWR hook calls=%d writes=%d want=1,2", calls.Load(), len(c.writes))
		}
		<-c.writes // CEA precedes the held DWA.
		answer, err := diam.ReadMessage(bytes.NewReader(<-c.writes), d)
		if err != nil {
			t.Fatal(err)
		}
		assertHeldDWA(t, request, answer)
	})
	t.Run("dialed", func(t *testing.T) {
		var calls atomic.Int32
		request := regressionDWR(t)
		setWireIdentity(t, request, avp.OriginHost, "peer.example")
		setWireIdentity(t, request, avp.OriginRealm, "example")
		p := newClientCoreTCP(t, func(cli *Client) {
			cli.Handler.cfg.OnHandshake = concurrentDWRHookInstallation(t, cli.Handler, request, &calls)
		})
		admitClientCoreTCP(t, p)
		answer, err := diam.ReadMessage(p.peer, p.client.Dict)
		if err != nil {
			t.Fatal(err)
		}
		assertHeldDWA(t, request, answer)
		if calls.Load() != 1 {
			t.Fatalf("DWR hook calls=%d want=1", calls.Load())
		}
	})
}

func assertHeldDWA(t *testing.T, request, answer *diam.Message) {
	t.Helper()
	if answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.ApplicationID != 0 || answer.Header.CommandFlags&diam.RequestFlag != 0 ||
		answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
		t.Fatalf("held DWA header = %+v; request = %+v", answer.Header, request.Header)
	}
	result, err := answer.FindAVP(avp.ResultCode, 0)
	if err != nil || result.Data != datatype.Unsigned32(diam.Success) {
		t.Fatalf("held DWA Result-Code = %v, %v; want success", result, err)
	}
}

// RFC 6733 §5.3: OnHandshake retains admission until it returns. A direct
// caller's held DWR must use the callback installed before admission releases.
func TestHeldDWRUsesHookInstalledByHandshake(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	cfg := testMessageErrorSettings(d)
	cfg.HandshakeTimeout = -1
	c := newHandshakeConn()
	var sm *StateMachine
	calls := 0
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) {
		sm.ServeDIAM(c, regressionDWR(t))
		if len(c.writes) != 1 {
			t.Fatal("held DWR crossed the handshake callback")
		}
		cfg.OnDWR = func(diam.Conn, *diam.Message) { calls++ }
	}
	sm = mustNewStateMachine(t, cfg, d)
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	s := sm.acceptedCore(c, nil, false)
	defer s.apply(protocol.Input{Kind: protocol.Abort})
	if calls != 1 || len(c.writes) != 2 {
		t.Fatalf("DWR hook calls=%d writes=%d want=1,2", calls, len(c.writes))
	}
}

// A prior held application callback can change hooks after all held batches
// have been prepared. Resolve each hook when its batch executes.
func TestHeldDWRUsesHookInstalledByEarlierHeldHandler(t *testing.T) {
	d := newSMTestDictionary(dict.Base())
	cfg := testMessageErrorSettings(d)
	cfg.HandshakeTimeout = -1
	c := newHandshakeConn()
	var sm *StateMachine
	calls := 0
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) {
		sm.ServeDIAM(c, diam.NewRequest(diam.ReAuth, 1001, d))
		sm.ServeDIAM(c, regressionDWR(t))
		if len(c.writes) != 1 {
			t.Fatal("held messages crossed the handshake callback")
		}
	}
	sm = mustNewStateMachine(t, cfg, d)
	sm.HandleIdx(diam.CommandIndex{Code: diam.ReAuth, AppID: 1001, Request: true}, diam.HandlerFunc(func(diam.Conn, *diam.Message) {
		cfg.OnDWR = func(diam.Conn, *diam.Message) { calls++ }
	}))
	sm.ServeDIAM(c, regressionCER(t, d, 1001))
	s := sm.acceptedCore(c, nil, false)
	defer s.apply(protocol.Input{Kind: protocol.Abort})
	if calls != 1 || len(c.writes) != 2 {
		t.Fatalf("DWR hook calls=%d writes=%d want=1,2", calls, len(c.writes))
	}
}
