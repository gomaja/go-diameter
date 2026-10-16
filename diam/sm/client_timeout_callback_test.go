package sm

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestClientTimeoutCallbackCompletesBeforeDialReturns(t *testing.T) {
	for _, tc := range []struct {
		name   string
		eof    bool
		cancel bool
	}{{"open-peer", false, false}, {"peer-eof", true, false}, {"open-peer-cancel", false, true}, {"peer-eof-cancel", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cli := newLivenessClient(t)
			cli.EnableWatchdog = false
			cli.RetransmitInterval = 80 * time.Millisecond
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			finished := make(chan struct{})
			cli.Handler.cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				if e.Err.Kind() == diam.ProtocolHandshakeTimeout {
					close(entered)
					<-release
					close(finished)
				}
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer closeDialTest(t, l)
			if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, e := cli.DialContext(ctx, "tcp", l.Addr().String(), nil)
				if c != nil {
					c.Close()
				}
				done <- e
			}()
			peer, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer closeDialTest(t, peer)
			if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = diam.ReadMessage(peer, cli.Dict); err != nil {
				t.Fatal(err)
			}
			if tc.eof {
				closeDialTest(t, peer)
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				unblock()
				t.Fatal("timeout callback did not begin")
			}
			if tc.cancel {
				cancel()
			}
			returned := false
			select {
			case err = <-done:
				returned = true
				t.Errorf("Dial returned %v while timeout callback remains blocked", err)
			case <-time.After(80 * time.Millisecond):
			}
			unblock()
			select {
			case <-finished:
			case <-time.After(10 * time.Second):
				t.Fatal("callback did not finish")
			}
			if !returned {
				select {
				case err = <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("Dial failed to finish")
				}
			}
			wantErr := ErrHandshakeTimeout
			if tc.cancel {
				wantErr = context.Canceled
			}
			if err != wantErr {
				t.Errorf("Dial error=%v, want %v", err, wantErr)
			}
		})
	}
}
