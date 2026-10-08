// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"net"
	"sync"
	"testing"
	"time"
)

// newTestConn builds a conn over a pipe, without a read loop. The tests below
// drive notifyClientGone and closeNotify directly, pinning the ordering they
// cover without depending on goroutine scheduling. The same failure is covered
// end to end by TestCloseNotifyAfterPeerGone in diam/sm.
func newTestConn(t *testing.T) (*conn, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	srv := &Server{Handler: NewServeMux()}
	return srv.newConn(local), remote
}

func closeRemote(t *testing.T, remote net.Conn) {
	t.Helper()
	if err := remote.Close(); err != nil {
		t.Errorf("close remote: %v", err)
	}
}

// TestCloseNotifyAfterClientGone verifies that a CloseNotify registration
// arriving after the read loop has already exited hands back a channel that
// is closed, rather than one that nothing is left alive to close.
//
// This is the sm.Client watchdog's ordering: Dial spawns the watchdog with
// go cli.watchdog(c, dwac), whose first statement is the CloseNotify
// registration. A peer FIN fully processed before that goroutine is
// scheduled used to leave the watchdog, and every later CloseNotify caller,
// parked on a channel that could never fire.
func TestCloseNotifyAfterClientGone(t *testing.T) {
	c, remote := newTestConn(t)
	defer closeRemote(t, remote)

	// Read loop exits before anything registers for notification.
	c.notifyClientGone()

	select {
	case <-c.closeNotify():
	case <-time.After(time.Second):
		t.Fatal("CloseNotify registered after the conn was gone never fired")
	}
}

// TestCloseNotifyRepeatedAfterClientGone verifies every later caller gets a
// closed channel too, not just the first one.
func TestCloseNotifyRepeatedAfterClientGone(t *testing.T) {
	c, remote := newTestConn(t)
	defer closeRemote(t, remote)

	c.notifyClientGone()

	for i := 0; i < 3; i++ {
		select {
		case <-c.closeNotify():
		case <-time.After(time.Second):
			t.Fatalf("CloseNotify call %d never fired", i)
		}
	}
}

// TestCloseNotifyBeforeClientGone covers the ordinary ordering: register
// first, then have the read loop exit.
func TestCloseNotifyBeforeClientGone(t *testing.T) {
	c, remote := newTestConn(t)
	defer closeRemote(t, remote)

	done := c.closeNotify()
	select {
	case <-done:
		t.Fatal("CloseNotify fired while the conn was still live")
	case <-time.After(50 * time.Millisecond):
	}

	c.notifyClientGone()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CloseNotify did not fire after the conn was gone")
	}
}

// TestNotifyClientGoneIsIdempotent guards against a double close panic when
// the read loop's defer runs after the pipe copy routine already reported.
func TestNotifyClientGoneIsIdempotent(t *testing.T) {
	c, remote := newTestConn(t)
	defer closeRemote(t, remote)

	done := c.closeNotify()
	c.notifyClientGone()
	c.notifyClientGone()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CloseNotify did not fire")
	}
}

// TestNotifyClientGoneLatchesWithoutRegistration is the direct check on the
// latch: the gone state must be recorded even when no channel exists yet.
func TestNotifyClientGoneLatchesWithoutRegistration(t *testing.T) {
	c, remote := newTestConn(t)
	defer closeRemote(t, remote)

	c.notifyClientGone()

	c.mu.Lock()
	gone := c.clientGone
	c.mu.Unlock()

	if !gone {
		t.Fatal("clientGone not latched when no channel was registered")
	}
}

// TestCloseNotifyConcurrentWithServeExit races CloseNotify registrations
// against the read loop exiting on a closed peer and against repeated
// disconnect reports. Every caller must get the same channel, it must be
// closed once the reports are in whichever order the scheduler picks, and
// repeated reports must not close it twice. The ordering where the disconnect
// is reported before anyone registers is pinned by
// TestCloseNotifyAfterClientGone, since concurrent reports would mask it here.
func TestCloseNotifyConcurrentWithServeExit(t *testing.T) {
	c, remote := newTestConn(t)
	closeRemote(t, remote)

	const callers = 32
	channels := make(chan (<-chan struct{}), callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		c.serve()
	}()
	for range callers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			channels <- c.writer.CloseNotify()
		}()
		go func() {
			defer wg.Done()
			<-start
			// The pipe copy routine and serve's exit both report the same
			// disconnect; extra reports must be harmless.
			c.notifyClientGone()
		}()
	}
	close(start)
	wg.Wait()
	close(channels)

	want := c.writer.CloseNotify()
	for got := range channels {
		if got != want {
			t.Error("concurrent CloseNotify callers got different channels")
		}
		select {
		case <-got:
		default:
			t.Error("a concurrent CloseNotify caller missed the disconnect")
		}
	}
}
