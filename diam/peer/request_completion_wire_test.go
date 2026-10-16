package peer

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func completionFireRequestTimer(t *testing.T, clock *fakeClock, index int) {
	t.Helper()
	clock.waitTimers(t, index+1)
	clock.mu.Lock()
	timer := clock.timers[index]
	clock.mu.Unlock()
	timer.mu.Lock()
	active := timer.active
	timer.active = false
	timer.mu.Unlock()
	if !active {
		t.Fatal("request timer was already stopped")
	}
	timer.f()
}

// The writer's selected request is still unsent while it waits before entering
// the native physical gate. Completion must cancel that exact write slot.
func TestManagerCompletedSelectedRequestOnWire(t *testing.T) {
	for _, finish := range []string{"cancel", "context deadline", "request deadline"} {
		t.Run(finish, func(t *testing.T) {
			m, c, clock, events := closingPeer(t, false)
			m.mu.RLock()
			s := m.peers["known.example.net"].activeSession.Load()
			m.mu.RUnlock()
			entered, release := make(chan struct{}), make(chan struct{})
			var released atomic.Bool
			unblock := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			t.Cleanup(unblock)
			s.beforePublication = func(msg *diam.Message) {
				if msg.Header.ApplicationID != 0 {
					close(entered)
					<-release
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			if finish == "context deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			mark := clock.timerCount()
			result := sendAsync(m, ctx, outboundRequest("known.example.net", "example.net"))
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not reach selected writer barrier")
			}
			m.pendingMu.Lock()
			var hop uint32
			var reuse *diam.Message
			for id, p := range m.pending[s] {
				hop = id
				copy := *p.msg
				header := *p.msg.Header
				header.HopByHopID = id
				copy.Header = &header
				reuse = &copy
			}
			m.pendingMu.Unlock()
			wantErr := error(context.Canceled)
			switch finish {
			case "cancel":
				cancel()
			case "context deadline":
				wantErr = context.DeadlineExceeded
			case "request deadline":
				wantErr = ErrRequestTimeout
				completionFireRequestTimer(t, clock, mark)
			}
			select {
			case got := <-result:
				if got.answer != nil || !errors.Is(got.err, wantErr) {
					t.Fatalf("completion=%+v, want %v", got, wantErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("selected request completion blocked behind writer")
			}
			if s.requests.HasPending() {
				t.Error("completion retained native answer ownership before admission")
			}
			m.pendingMu.Lock()
			_, retained := m.controls[s][hop]
			atomic.StoreUint32(&m.nextHop, hop-1)
			candidate := m.nextHopIDLocked(s, 0, false)
			m.pendingMu.Unlock()
			if !retained || candidate == hop {
				t.Error("selected completed write lost its identifier reservation")
			}
			// A following answer joins this writer without creating new request
			// ownership; receipt proves the selected slot has been drained.
			sentinel, err := base.BuildDWA(watchdogRequest(t), m.baseSettings(s.c))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.send(sentinel, false); err != nil {
				t.Fatal(err)
			}
			unblock()
			for {
				msg := read(t, c)
				if msg.Header.CommandCode == diam.DeviceWatchdog && msg.Header.HopByHopID == sentinel.Header.HopByHopID {
					break
				}
				t.Errorf("completed request reached transport: %+v", msg.Header)
			}
			if s.requests.HasPending() {
				t.Error("completed selected write leaked native answer ownership")
			}
			m.pendingMu.Lock()
			pending, controls := len(m.pending[s]), len(m.controls[s])
			m.pendingMu.Unlock()
			if pending != 0 || controls != 0 {
				t.Fatalf("writer drain retained reservations: pending=%d controls=%d", pending, controls)
			}
			// The exact completed header must be reusable after writer release.
			// A leaked cancelled native reservation rejects this fresh write.
			if _, err := reuse.WriteTo(s.c); err != nil {
				t.Fatalf("writer drain retained cancelled native reservation: %v", err)
			}
			probe := read(t, c)
			if probe.Header.HopByHopID != reuse.Header.HopByHopID || probe.Header.EndToEndID != reuse.Header.EndToEndID {
				t.Fatalf("fresh same-header probe mismatch: %+v", probe.Header)
			}
			if !s.requests.MatchAnswer(probe.Answer(diam.Success), true) || s.requests.HasPending() {
				t.Fatal("fresh same-header probe did not release native ownership")
			}
			select {
			case e := <-events:
				t.Fatalf("request completion invoked protocol hook: %+v", e)
			default:
			}
		})
	}
}

func TestManagerCompletedSentRequestClearsOwnershipOnWire(t *testing.T) {
	for _, timer := range []bool{false, true} {
		t.Run(fmt.Sprintf("request timer=%t", timer), func(t *testing.T) {
			m, c, clock, _ := closingPeer(t, false)
			m.mu.RLock()
			s := m.peers["known.example.net"].activeSession.Load()
			m.mu.RUnlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mark := clock.timerCount()
			result := sendAsync(m, ctx, outboundRequest("known.example.net", "example.net"))
			request := read(t, c)
			if request.Header.CommandCode != 272 || !s.requests.HasPending() {
				t.Fatal("sent request has no native owner")
			}
			wantErr := error(context.Canceled)
			if timer {
				wantErr = ErrRequestTimeout
				completionFireRequestTimer(t, clock, mark)
			} else {
				cancel()
			}
			if got := <-result; got.answer != nil || !errors.Is(got.err, wantErr) {
				t.Fatalf("sent completion=%+v, want %v", got, wantErr)
			}
			if s.requests.HasPending() {
				t.Fatal("completion retained sent native request ownership")
			}
		})
	}
}
