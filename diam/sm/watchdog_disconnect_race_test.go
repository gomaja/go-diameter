package sm

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// disconnectCleanupConn separates entry into Close from publication of
// Closed, matching the interval in which a transport close may be blocked.
type disconnectCleanupConn struct {
	*acceptedWatchdogProbeConn
	closeEntered chan struct{}
	allowClose   chan struct{}
	closeNotify  chan struct{}
	closeOnce    sync.Once
}

type watchdogRegistrationConn struct {
	*disconnectCleanupConn
	lookupEntered chan struct{}
	allowLookup   chan struct{}
}

func (c *watchdogRegistrationConn) DispatchDone() <-chan struct{} {
	close(c.lookupEntered)
	<-c.allowLookup
	return c.done
}

// RFC 6733 §5.6: a Disconnect that finishes before watchdog registration
// leaves Closed as the durable indication that supervision cannot start.
func TestAcceptedWatchdogDisconnectFinishesBeforeRegistration(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	synctest.Test(t, func(t *testing.T) {
		cfg := newAcceptedWatchdogSettings()
		sm := mustNewStateMachine(t, &cfg, testDict)
		c := &watchdogRegistrationConn{
			disconnectCleanupConn: newDisconnectCleanupConn(),
			lookupEntered:         make(chan struct{}), allowLookup: make(chan struct{}),
		}
		close(c.allowClose)
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		defer close(c.done)
		handled := make(chan struct{})
		go func() { sm.ServeDIAM(c, regressionCER(t, testDict, 1001)); close(handled) }()
		<-c.lookupEntered // The first Closed check has passed; registration has not.
		<-c.writes        // CEA
		disconnected := make(chan error, 1)
		go func() { disconnected <- sm.Disconnect(c, DisconnectRebooting, time.Hour) }()
		dpr, err := diam.ReadMessage(bytes.NewReader(<-c.writes), testDict)
		if err != nil || dpr.Header.CommandCode != diam.DisconnectPeer {
			t.Fatalf("DPR: %v, %v", dpr, err)
		}
		// Isolate cleanup while the CER handler still holds admission.
		sm.acceptedCore(c, nil, false).apply(protocol.Input{Kind: protocol.Receive, Message: acceptedDWA(t, dpr, diam.Success)})
		if err := <-disconnected; err != nil {
			t.Fatal(err)
		}
		close(c.allowLookup)
		<-handled
		if _, ok := acceptedTestSupervisor(sm, c); ok {
			t.Error("completed Disconnect acquired a watchdog after its pending entry was removed")
		}
	})
}

func newDisconnectCleanupConn() *disconnectCleanupConn {
	return &disconnectCleanupConn{
		acceptedWatchdogProbeConn: newAcceptedWatchdogProbeConn(),
		closeEntered:              make(chan struct{}),
		allowClose:                make(chan struct{}),
		closeNotify:               make(chan struct{}),
	}
}

func (c *disconnectCleanupConn) CloseNotify() <-chan struct{} { return c.closeNotify }
func (c *disconnectCleanupConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closeEntered)
		<-c.allowClose
		c.acceptedWatchdogProbeConn.Close()
		close(c.closeNotify)
	})
}

// RFC 6733 §5.6: Disconnect enters Closing before its DPR. The deferred
// start after OnHandshake must observe that state until Close publishes Closed.
func TestAcceptedWatchdogDisconnectCleanupCannotRestart(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	cfg := newAcceptedWatchdogSettings()
	cfg.WatchdogInterval = time.Hour
	handshakeEntered := make(chan struct{})
	allowHandshake := make(chan struct{})
	cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) {
		close(handshakeEntered)
		<-allowHandshake
	}
	sm := mustNewStateMachine(t, &cfg, testDict)
	c := newDisconnectCleanupConn()
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	var releaseHandshake, releaseClose sync.Once
	unblockHandshake := func() { releaseHandshake.Do(func() { close(allowHandshake) }) }
	unblockClose := func() { releaseClose.Do(func() { close(c.allowClose) }) }
	handlerDone := make(chan struct{})
	request := regressionCER(t, testDict, 1001)
	go func() { sm.ServeDIAM(c, request); close(handlerDone) }()
	disconnectDone := make(chan error, 1)
	disconnectStarted, disconnectRead := false, false
	defer func() {
		unblockHandshake()
		unblockClose()
		close(c.done)
		<-handlerDone
		if disconnectStarted && !disconnectRead {
			select {
			case err := <-disconnectDone:
				if err != nil {
					t.Errorf("Disconnect: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("Disconnect goroutine did not finish during cleanup")
			}
		}
	}()
	cea, err := diam.ReadMessage(bytes.NewReader(<-c.writes), testDict)
	if err != nil || !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA: %v, %v", cea, err)
	}
	<-handshakeEntered
	disconnectStarted = true
	go func() { disconnectDone <- sm.Disconnect(c, DisconnectRebooting, time.Hour) }()
	dpr, err := diam.ReadMessage(bytes.NewReader(<-c.writes), testDict)
	if err != nil || dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("DPR: %v, %v", dpr, err)
	}
	// The CER admission barrier deliberately holds later ServeDIAM calls.
	// Feed the validated DPA to the core executor on the dispatch goroutine
	// while the transport's Close remains blocked.
	dpaDone := make(chan struct{})
	defer func() { unblockClose(); <-dpaDone }()
	answer := acceptedDWA(t, dpr, diam.Success)
	go func() {
		sm.acceptedCore(c, nil, false).apply(protocol.Input{Kind: protocol.Receive, Message: answer})
		close(dpaDone)
	}()
	select {
	case <-c.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect did not enter deferred Close after DPA")
	}
	if c.Closed() {
		t.Fatal("test Close published Closed before its release")
	}
	unblockHandshake()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("CER handler did not finish after OnHandshake release")
	}
	if _, ok := acceptedTestSupervisor(sm, c); ok {
		t.Fatal("deferred watchdog startup registered during Disconnect cleanup")
	}
	unblockClose()
	select {
	case err := <-disconnectDone:
		disconnectRead = true
		if err != nil {
			t.Fatalf("Disconnect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect did not finish after Close release")
	}
}
