package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func peerClosingForLocalDisconnect(t *testing.T, enabled bool) *Core {
	t.Helper()
	c := opened(t, func(cfg *Config) {
		cfg.LocalDisconnectInClosing = enabled
		cfg.ClosingTimeout = 10 * time.Second
	})
	es := fence(t, c, receive(request(t, diam.DisconnectPeer)), false)
	c.Handle(complete(find(t, es, Send)))
	if c.Snapshot().Phase() != Closing || !c.Snapshot().Frozen() {
		t.Fatal("peer DPR did not retain frozen Closing")
	}
	return c
}

// RFC 6733 §§5.4–5.6: the StateMachine compatibility option preserves a
// subsequent local DPR without replacing the peer's original Wait-Returns.
func TestLocalDisconnectAfterPeerDPRDeadlines(t *testing.T) {
	for _, ending := range []string{"matched-DPA", "local-timeout", "receiver-deadline"} {
		t.Run(ending, func(t *testing.T) {
			c := peerClosingForLocalDisconnect(t, true)
			receiver := c.Snapshot().Timer(ClosingTimer)
			if receiver.Token == 0 || !receiver.Deadline.Equal(epoch.Add(10*time.Second)) {
				t.Fatalf("original receiver deadline=%+v", receiver)
			}
			local := event(Disconnect)
			local.At = epoch.Add(2 * time.Second)
			local.Timeout = 3 * time.Second
			if ending == "receiver-deadline" {
				local.Timeout = 20 * time.Second
			}
			local.Cause, local.Token = 1, 911
			es := c.Handle(local)
			wantKinds(t, es, ArmTimer, ReserveIDs)
			armed := find(t, es, ArmTimer)
			if armed.Timer != ReceiverDisconnectTimer || !armed.Deadline.Equal(local.At.Add(local.Timeout)) {
				t.Fatalf("local timer=%+v", armed)
			}
			sent := grant(t, c, es)
			c.Handle(complete(sent))
			localTimer := c.Snapshot().Timer(ReceiverDisconnectTimer)
			controls := c.Snapshot().Controls()
			if c.Snapshot().Timer(ClosingTimer) != receiver || c.Snapshot().Phase() != Closing || !c.Snapshot().Frozen() || c.Snapshot().Ready() {
				t.Fatal("local DPR changed the original receiver deadline or reopened admission")
			}
			duplicate := local
			duplicate.Token++
			pending := c.Handle(duplicate)
			wantKinds(t, pending, Notify)
			if pending[0].Notification.Kind != DisconnectNotice || pending[0].Notification.Outcome != AlreadyPending {
				t.Fatalf("duplicate local Disconnect=%+v", pending)
			}
			repeated := receive(request(t, diam.DisconnectPeer))
			repeated.At = epoch.Add(4 * time.Second)
			reply := c.Handle(repeated)
			wantKinds(t, reply, Send)
			wantKinds(t, c.Handle(complete(reply[0])))
			if c.Snapshot().Timer(ClosingTimer) != receiver || c.Snapshot().Timer(ReceiverDisconnectTimer) != localTimer {
				t.Fatal("repeated peer DPR or local Disconnect changed either deadline")
			}
			if got := c.Snapshot().Controls(); len(got) != len(controls) || len(got) != 1 || got[0] != controls[0] {
				t.Fatalf("repeated peer DPR changed local reservation: before=%+v after=%+v", controls, got)
			}
			want := Completed
			switch ending {
			case "matched-DPA":
				answer, err := base.BuildDPAResult(sent.Message, remote(t).Local, diam.Success)
				if err != nil {
					t.Fatal(err)
				}
				es = c.Handle(receive(answer))
			case "local-timeout", "receiver-deadline":
				expiry := event(TimerExpired)
				expiry.Timer, expiry.Token, expiry.At = ReceiverDisconnectTimer, localTimer.Token, localTimer.Deadline
				want = TimedOut
				if ending == "receiver-deadline" {
					expiry.Timer, expiry.Token, expiry.At = ClosingTimer, receiver.Token, receiver.Deadline
					want = ConnectionClosed
				}
				es = c.Handle(expiry)
			}
			find(t, es, Close)
			var completions, timeouts int
			for _, e := range es {
				if e.Kind != Notify {
					continue
				}
				if e.Notification.Kind == DisconnectNotice {
					completions++
					if e.Token != local.Token || e.Notification.Outcome != want {
						t.Fatalf("local result=%+v want token=%d outcome=%v", e, local.Token, want)
					}
				}
				if e.Notification.Protocol == diam.ProtocolDisconnectTimeout {
					timeouts++
					if !e.Notification.Closing || (e.Notification.Diagnostic == "local-disconnect") != (ending == "local-timeout") {
						t.Fatalf("timeout attribution=%+v", e.Notification)
					}
				}
			}
			if completions != 1 || (ending != "matched-DPA" && timeouts != 1) || (ending == "matched-DPA" && timeouts != 0) {
				t.Fatalf("completion count=%d timeout count=%d", completions, timeouts)
			}
			if c.Snapshot().Phase() != Closed || c.Snapshot().Timer(ClosingTimer).Token != 0 || c.Snapshot().Timer(ReceiverDisconnectTimer).Token != 0 || len(c.Snapshot().Controls()) != 0 {
				t.Fatal("completion retained a deadline, reservation, or live phase")
			}
			for timer, snapshot := range map[TimerKind]TimerSnapshot{ClosingTimer: receiver, ReceiverDisconnectTimer: localTimer} {
				late := event(TimerExpired)
				late.Timer, late.Token, late.At = timer, snapshot.Token, snapshot.Deadline
				wantKinds(t, c.Handle(late))
			}
		})
	}
}

func TestLocalDisconnectAfterPeerDPRRequiresCompatibilityOption(t *testing.T) {
	c := peerClosingForLocalDisconnect(t, false)
	receiver := c.Snapshot().Timer(ClosingTimer)
	local := event(Disconnect)
	local.Token, local.Timeout = 912, time.Second
	es := c.Handle(local)
	wantKinds(t, es, Notify)
	if es[0].Notification.Kind != DisconnectNotice || es[0].Notification.Outcome != NotOpen {
		t.Fatalf("default core accepted local DPR in Closing: %+v", es)
	}
	if c.Snapshot().Timer(ClosingTimer) != receiver || c.Snapshot().Timer(ReceiverDisconnectTimer).Token != 0 || len(c.Snapshot().Controls()) != 0 {
		t.Fatal("default rejection changed receiver lifetime or allocated local exchange")
	}
}

func TestLocalDisconnectAfterPeerDPRTerminalCleanup(t *testing.T) {
	for _, ending := range []string{"retired", "transport-lost", "failed-writer", "short-writer"} {
		t.Run(ending, func(t *testing.T) {
			c := peerClosingForLocalDisconnect(t, true)
			local := event(Disconnect)
			local.At, local.Timeout, local.Token = epoch.Add(time.Second), 2*time.Second, 913
			sent := grant(t, c, c.Handle(local))
			receiver, caller := c.Snapshot().Timer(ClosingTimer), c.Snapshot().Timer(ReceiverDisconnectTimer)
			if receiver.Token == 0 || caller.Token == 0 {
				t.Fatal("crossed disconnect did not arm both timers")
			}
			finish := complete(sent)
			phase := Closed
			switch ending {
			case "retired":
				finish, phase = event(Retire), Retired
			case "transport-lost":
				finish = event(TransportLost)
			case "failed-writer":
				finish.Err = errors.New("synthetic crossed DPR writer failure")
			case "short-writer":
				finish.Bytes--
			}
			es := c.Handle(finish)
			var notices, stopped int
			for _, e := range es {
				if e.Kind == Notify && e.Notification.Kind == DisconnectNotice {
					notices++
					if e.Token != local.Token || e.Notification.Outcome != ConnectionClosed {
						t.Fatalf("terminal local result=%+v", e)
					}
				}
				if e.Kind == StopTimer && (e.Timer == ClosingTimer || e.Timer == ReceiverDisconnectTimer) {
					stopped++
				}
				if ending == "retired" && e.Kind == Close {
					t.Fatal("retirement closed the physical transport")
				}
			}
			if ending != "retired" {
				find(t, es, Close)
			}
			if notices != 1 || stopped != 2 || c.Snapshot().Phase() != phase || c.Snapshot().Timer(ClosingTimer).Token != 0 || c.Snapshot().Timer(ReceiverDisconnectTimer).Token != 0 {
				t.Fatalf("terminal cleanup: notices=%d stopped=%d phase=%v", notices, stopped, c.Snapshot().Phase())
			}
			if ending == "retired" || ending == "transport-lost" {
				if got := c.Snapshot().Controls(); len(got) != 1 || got[0].Logical || got[0].Writers != 1 {
					t.Fatalf("terminal event lost selected writer ownership: %+v", got)
				}
				wantKinds(t, c.Handle(complete(sent)), ReleaseIDs)
			}
			if len(c.Snapshot().Controls()) != 0 || len(c.operations) != 0 || c.disconnectWaiting {
				t.Fatal("terminal cleanup retained waiter, writer, or identifiers")
			}
			wantKinds(t, c.Handle(complete(sent)))
			for timer, snapshot := range map[TimerKind]TimerSnapshot{ClosingTimer: receiver, ReceiverDisconnectTimer: caller} {
				late := event(TimerExpired)
				late.Timer, late.Token, late.At = timer, snapshot.Token, snapshot.Deadline
				wantKinds(t, c.Handle(late))
			}
		})
	}
}
