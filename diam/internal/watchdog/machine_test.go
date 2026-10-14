package watchdog

import "testing"

// Each row follows RFC 3539 Appendix A's state machine table. Close actions
// leave Pending alone until the caller releases the connection's control work.
func TestRFC3539AppendixA(t *testing.T) {
	rows := []struct {
		name    string
		before  Machine
		event   Event
		after   Machine
		actions Actions
	}{
		{"INITIAL/down", Machine{State: Initial}, ConnectionDown, Machine{State: Down}, Actions{Close: true}},
		{"DOWN/down", Machine{State: Down}, ConnectionDown, Machine{State: Down}, Actions{Close: true}},
		{"INITIAL/up", Machine{State: Initial}, ConnectionUp, Machine{State: Okay}, Actions{Reset: true}},
		{"INITIAL/timer", Machine{State: Initial}, Expired, Machine{State: Initial}, Actions{Open: true, Reset: true}},
		{"INITIAL/DWA", Machine{State: Initial, Pending: true}, ReceiveDWA, Machine{State: Initial}, Actions{Discard: true}},
		{"INITIAL/other", Machine{State: Initial}, Receive, Machine{State: Initial}, Actions{Discard: true}},
		{"OKAY/DWA", Machine{State: Okay, Pending: true}, ReceiveDWA, Machine{State: Okay}, Actions{Reset: true}},
		{"OKAY/other", Machine{State: Okay, Pending: true}, Receive, Machine{State: Okay, Pending: true}, Actions{Reset: true}},
		{"OKAY/idle_timer", Machine{State: Okay}, Expired, Machine{State: Okay, Pending: true}, Actions{Send: true, Reset: true}},
		{"OKAY/pending_timer", Machine{State: Okay, Pending: true}, Expired, Machine{State: Suspect, Pending: true}, Actions{Failover: true, Reset: true}},
		{"OKAY/down", Machine{State: Okay, Pending: true}, ConnectionDown, Machine{State: Down, Pending: true}, Actions{Close: true, Failover: true, Reset: true}},
		{"SUSPECT/DWA", Machine{State: Suspect, Pending: true}, ReceiveDWA, Machine{State: Okay}, Actions{Failback: true, Reset: true}},
		{"SUSPECT/other", Machine{State: Suspect, Pending: true}, Receive, Machine{State: Okay, Pending: true}, Actions{Failback: true, Reset: true}},
		{"SUSPECT/timer", Machine{State: Suspect, Pending: true}, Expired, Machine{State: Down, Pending: true}, Actions{Close: true, Reset: true}},
		{"SUSPECT/down", Machine{State: Suspect, Pending: true}, ConnectionDown, Machine{State: Down, Pending: true}, Actions{Close: true, Reset: true}},
		{"DOWN/timer", Machine{State: Down}, Expired, Machine{State: Down}, Actions{Open: true, Reset: true}},
		{"DOWN/up", Machine{State: Down, NumDWA: 9}, ConnectionUp, Machine{State: Reopen, Pending: true}, Actions{Send: true, Reset: true}},
		{"DOWN/DWA", Machine{State: Down, Pending: true}, ReceiveDWA, Machine{State: Down}, Actions{Discard: true}},
		{"DOWN/other", Machine{State: Down}, Receive, Machine{State: Down}, Actions{Discard: true}},
		{"REOPEN/DWA_zero", Machine{State: Reopen, Pending: true}, ReceiveDWA, Machine{State: Reopen, NumDWA: 1}, Actions{}},
		{"REOPEN/DWA_one", Machine{State: Reopen, Pending: true, NumDWA: 1}, ReceiveDWA, Machine{State: Reopen, NumDWA: 2}, Actions{}},
		{"REOPEN/DWA_two", Machine{State: Reopen, Pending: true, NumDWA: 2}, ReceiveDWA, Machine{State: Okay, NumDWA: 3}, Actions{Failback: true}},
		{"REOPEN/late_DWA", Machine{State: Reopen, Pending: true, NumDWA: -1}, ReceiveDWA, Machine{State: Reopen}, Actions{}},
		{"REOPEN/other", Machine{State: Reopen, Pending: true, NumDWA: 1}, Receive, Machine{State: Reopen, Pending: true, NumDWA: 1}, Actions{Discard: true}},
		{"REOPEN/idle_timer", Machine{State: Reopen, NumDWA: 1}, Expired, Machine{State: Reopen, Pending: true, NumDWA: 1}, Actions{Send: true, Reset: true}},
		{"REOPEN/first_miss", Machine{State: Reopen, Pending: true, NumDWA: 2}, Expired, Machine{State: Reopen, Pending: true, NumDWA: -1}, Actions{Reset: true}},
		{"REOPEN/second_miss", Machine{State: Reopen, Pending: true, NumDWA: -1}, Expired, Machine{State: Down, Pending: true, NumDWA: -1}, Actions{Close: true, Reset: true}},
		{"REOPEN/down", Machine{State: Reopen, Pending: true, NumDWA: 1}, ConnectionDown, Machine{State: Down, Pending: true, NumDWA: 1}, Actions{Close: true, Reset: true}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			before := row.before
			after, actions := before.Step(row.event)
			if after != row.after || actions != row.actions {
				t.Fatalf("Step(%+v, %v) = %+v / %+v; want %+v / %+v", before, row.event, after, actions, row.after, row.actions)
			}
			if before != row.before {
				t.Fatal("Step changed its input")
			}
		})
	}
}

// RFC 3539 §3.4.1 [5] and Appendix A: initial admission needs no probes;
// recovery waits for three responses, restarting the count after a missed Tw.
func TestRFC3539RecoveryTrace(t *testing.T) {
	m, a := (Machine{State: Initial}).Step(ConnectionUp)
	if m.State != Okay || a.Send {
		t.Fatalf("initial admission: %+v / %+v", m, a)
	}
	m, _ = m.Step(ConnectionDown)
	m.Pending = false // the caller releases control requests on transport loss
	m, a = m.Step(ConnectionUp)
	if m.State != Reopen || !a.Send {
		t.Fatalf("recovery admission: %+v / %+v", m, a)
	}
	m, _ = m.Step(ReceiveDWA)
	m, _ = m.Step(Expired)
	m, _ = m.Step(Expired)    // first unanswered window resets the recovery count
	m, _ = m.Step(ReceiveDWA) // a late answer brings -1 to zero
	if m.State != Reopen || m.NumDWA != 0 {
		t.Fatalf("late answer: %+v", m)
	}
	for n := 1; n <= 3; n++ {
		m, a = m.Step(Expired)
		if !a.Send || !m.Pending {
			t.Fatalf("probe %d: %+v / %+v", n, m, a)
		}
		m, a = m.Step(ReceiveDWA)
		if m.NumDWA != n || m.Pending || (m.State == Okay) != (n == 3) || a.Failback != (n == 3) {
			t.Fatalf("answer %d: %+v / %+v", n, m, a)
		}
	}
}
