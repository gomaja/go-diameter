package sm

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestDefaultHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm := mustNewStateMachine(t, &Settings{})
		c := newErrWriteConn()
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		start := time.Now()
		<-c.CloseNotify()
		if elapsed := time.Since(start); elapsed != 30*time.Second || DefaultHandshakeTimeout != 30*time.Second {
			t.Fatalf("default handshake timeout = %s, want 30s", elapsed)
		}
	})
}

func TestHandshakeTimerStopsOnSuccessAndClose(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 := cloneTestSettings(serverSettings2, testDict)

	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "success"}[success], func(t *testing.T) {
			settings := *serverSettings2
			settings.HandshakeTimeout = time.Hour
			sm := mustNewStateMachine(t, &settings, testDict)
			c := &messageErrorCaptureConn{dictionary: testDict, ctx: context.Background()}
			cleanup := sm.HandleAccept(c)
			defer cleanup()
			value, ok := sm.accepted.Load(c)
			if !ok {
				t.Fatal("missing accepted connection")
			}
			state := value.(*acceptedHandshake)
			if success {
				sm.ServeDIAM(c, regressionCER(t, testDict, 1001))
			} else {
				cleanup()
			}
			if state.timers[protocol.HandshakeTimer].Stop() {
				t.Fatal("handshake timer was still active")
			}
		})
	}
}

func TestAcceptedConnectionCleanupReleasesTimer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings := cloneTestSettings(serverSettings, testDict)

	sm := mustNewStateMachine(t, serverSettings, testDict)
	opened := make(chan diam.Conn, 1)
	srv := diamtest.NewUnstartedServer(sm, testDict)
	srv.Config.OnNewConnection = func(c diam.Conn) { opened <- c }
	srv.Start()
	defer srv.Close()
	peer, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	var c diam.Conn
	select {
	case c = <-opened:
	case <-time.After(time.Second):
		t.Fatal("accept hook did not finish")
	}
	value, ok := sm.accepted.Load(c)
	if !ok {
		t.Fatal("missing accepted connection")
	}
	state := value.(*acceptedHandshake)
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, c).DispatchDone():
	case <-time.After(time.Second):
		t.Fatal("connection did not finish")
	}
	if _, ok = sm.accepted.Load(c); ok {
		t.Fatal("closed connection retained")
	}
	if state.timers[protocol.HandshakeTimer].Stop() {
		t.Fatal("closed connection retained an active timer")
	}
}

func TestNegativeHandshakeTimeoutCreatesNoTimer(t *testing.T) {
	testDict := newSMTestDictionary(dict.Base())
	serverSettings := cloneTestSettings(serverSettings, testDict)

	settings := *serverSettings
	settings.HandshakeTimeout = -1
	sm := mustNewStateMachine(t, &settings, testDict)
	c := newErrWriteConn(testDict)
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	value, ok := sm.accepted.Load(c)
	if !ok {
		t.Fatal("disabled timeout lost admission state")
	}
	if value.(*acceptedHandshake).timers[protocol.HandshakeTimer] != nil {
		t.Fatal("disabled handshake timeout created a timer")
	}
}
