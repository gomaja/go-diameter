package sm

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type validDWRGatedHandler struct {
	*StateMachine
	cerEntered, release, dwrEntered, dwrDone chan struct{}
}

func (h *validDWRGatedHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == diam.CapabilitiesExchange {
		close(h.cerEntered)
		<-h.release
	} else {
		close(h.dwrEntered)
		defer close(h.dwrDone)
	}
	h.StateMachine.ServeDIAM(c, m)
}
func TestSMConcurrentCERThenValidDWROnWire(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	h := &validDWRGatedHandler{StateMachine: mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict), cerEntered: make(chan struct{}), release: make(chan struct{}), dwrEntered: make(chan struct{}), dwrDone: make(chan struct{})}
	srv := diamtest.NewUnstartedServer(h, testDict)
	srv.Config.MaxConcurrentHandlers = 4
	srv.Start()
	defer srv.Close()
	var once sync.Once
	release := func() { once.Do(func() { close(h.release) }) }
	defer release()
	c, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err = c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = regressionCER(t, testDict, 1001).WriteTo(c); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.cerEntered:
	case <-time.After(time.Second):
		t.Fatal("CER callback missing")
	}
	if _, err = regressionDWR(t).WriteTo(c); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.dwrEntered:
	case <-time.After(time.Second):
		t.Fatal("DWR callback missing")
	}
	select {
	case <-h.dwrDone:
		t.Error("DWR processed before held CER")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog} {
		a, e := diam.ReadMessage(c, testDict)
		if e != nil || a.Header.CommandCode != cmd || !testResultCode(a, diam.Success) {
			t.Fatalf("want %d/2001: %v %v", cmd, a, e)
		}
	}
}
func TestInvalidDWAHeaderDoesNotResetActivity(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	records := logtest.New()
	sm := mustNewStateMachine(t, testMessageErrorSettings(testDict), testDict)
	activity := newWatchdogActivity()
	activity.ceaReceived.Store(true)
	activity.last.Store(123)
	called := false
	h := activityHandler{StateMachine: sm, activity: activity, dwa: watchdogDWAHandler(func(diam.Conn, *diam.Message, watchdogReceipt) { called = true })}
	c := loggerHandshakeConn{newHandshakeConn(), records.Logger()}
	m := diam.NewMessage(diam.DeviceWatchdog, 0, 4, 1, 2, testDict)
	h.ServeDIAM(c, m)
	if activity.last.Load() != 123 {
		t.Error("invalid DWA reset last activity")
	}
	select {
	case <-activity.signal:
		t.Error("invalid DWA signalled watchdog activity")
	default:
	}
	if called {
		t.Fatal("invalid DWA reached watchdog handler")
	}
	_ = waitLog(t, records, 1)
	m.Header.ApplicationID = 0
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
	h.ServeDIAM(c, m)
	if activity.last.Load() == 123 || !called {
		t.Fatal("valid DWA did not update activity")
	}
}
