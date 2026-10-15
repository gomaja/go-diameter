package peer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestDialCompletionAfterAuthorizationEnds(t *testing.T) {
	for _, mode := range []string{"static-deadline", "static-cancel", "lease-expiry"} {
		t.Run(mode, func(t *testing.T) {
			clock := &fakeClock{}
			raw, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			attempts := make(chan struct{}, 2)
			m, err := New(Config{Settings: testSettings("local.example.net"), Clock: clock, Dial: func(context.Context, Endpoint) (net.Conn, error) {
				attempts <- struct{}{}
				return raw, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			a := &actor{m: m, cfg: PeerConfig{Host: "remote.example.net", Endpoints: []Endpoint{{Address: "remote.example.net:3868"}}}, events: make(chan event, 16), done: make(chan struct{}), state: Closed, dialing: true, pendingGen: 7, nextGen: 7}
			a.publish(nil)
			t.Cleanup(func() { close(a.done); a.stopTimer(); a.stopReconnect(); closeManager(t, m, nil) })
			s, err := m.dialEndpoint(context.Background(), a.cfg.Endpoints[0], a, 7)
			if err != nil {
				t.Fatal(err)
			}
			<-attempts
			ctx := context.Background()
			want := context.DeadlineExceeded
			switch mode {
			case "static-deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "static-cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "lease-expiry":
				spec := discoverySpec()
				spec.ExpiresAt = time.Now().Add(-time.Second)
				a.discovery.Store(&discoveryState{spec: spec, expires: spec.ExpiresAt})
				want = ErrLeaseExpired
			}
			// The transport has succeeded; end authorization before handing it to
			// the actor. This boundary uses no sleeps or scheduler-dependent deadlines.
			a.finishDial(ctx, s, 7)
			var completion *event
			for len(a.events) > 0 {
				e := <-a.events
				if e.kind == dialDone {
					completion = &e
					break
				}
			}
			if completion == nil {
				t.Fatal("successful dial lost completion after authorization ended; dialing remains true")
			}
			if completion.gen != 7 || completion.s != nil || !errors.Is(completion.err, want) {
				t.Fatalf("completion = %+v, want generation 7 and %v", *completion, want)
			}
			select {
			case <-s.closed:
			default:
				t.Fatal("expired successful session was not closed")
			}
			a.onDial(*completion)
			if a.dialing {
				t.Fatal("matching completion did not clear pending dial")
			}
			// A late completion must not clear a newer worker's ownership.
			a.pendingGen = 8
			a.dialing = true
			a.onDial(*completion)
			if !a.dialing {
				t.Fatal("stale completion cleared newer dial")
			}
			a.dialing = false
			if mode == "lease-expiry" {
				return
			}
			m.started = true
			m.runCtx = context.Background()
			a.reconnectTick()
			select {
			case <-attempts:
			case <-time.After(time.Second):
				t.Fatal("static reconnect never attempted another dial")
			}
		})
	}
}

func TestRetiredDialCompletion(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "current-generation"
		if stale {
			name = "stale-generation"
		}
		t.Run(name, func(t *testing.T) {
			raw, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			attempts := make(chan struct{}, 2)
			notifications := make(chan PeerEvent, 8)
			m, err := New(Config{Settings: testSettings("local.example.net"), Clock: &fakeClock{}, OnPeerEvent: func(e PeerEvent) { notifications <- e }, Dial: func(context.Context, Endpoint) (net.Conn, error) {
				attempts <- struct{}{}
				return raw, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			a := &actor{m: m, cfg: PeerConfig{Host: "remote.example.net", Endpoints: []Endpoint{{Address: "remote.example.net:3868"}}}, events: make(chan event, 16), done: make(chan struct{}), state: WaitConnAck, dialing: true, pendingGen: 7, nextGen: 7}
			a.publish(nil)
			t.Cleanup(func() { close(a.done); a.stopTimer(); a.stopReconnect(); closeManager(t, m, nil) })
			s, err := m.dialEndpoint(context.Background(), a.cfg.Endpoints[0], a, 7)
			if err != nil {
				t.Fatal(err)
			}
			<-attempts
			a.finishDial(context.Background(), s, 7)
			completion := <-a.events
			if completion.kind != dialDone || completion.s != s {
				t.Fatalf("successful dial completion = %+v", completion)
			}
			// Retirement wins after publication and before actor consumption.
			// The queued completion still owns its pending dial generation.
			s.retired.Store(true)
			if stale {
				a.pendingGen = 8
			}
			a.handle(completion)
			if stale {
				if !a.dialing || a.state != WaitConnAck || a.i != nil {
					t.Fatal("stale retired completion changed newer dial")
				}
			} else {
				if a.dialing {
					t.Fatal("retired successful completion was dropped; dialing remains true")
				}
				if a.state != Closed || a.i != nil {
					t.Fatalf("retired completion admitted unusable session: state=%s initiator=%p", a.state, a.i)
				}
				select {
				case notification := <-notifications:
					if !errors.Is(notification.Reason, diam.ErrConnectionRetired) {
						t.Fatalf("retired completion reason = %v", notification.Reason)
					}
				case <-time.After(time.Second):
					t.Fatal("retired completion did not report failure")
				}
			}
			select {
			case <-s.closed:
			default:
				t.Fatal("retired successful transport was not closed")
			}
			if stale {
				return
			}
			m.started = true
			m.runCtx = context.Background()
			a.reconnectTick()
			select {
			case <-attempts:
			case <-time.After(time.Second):
				t.Fatal("static reconnect stalled after retired dial completion")
			}
		})
	}
}
