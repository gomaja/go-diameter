// Package watchdog implements the transport-independent algorithm in RFC 3539
// §3.4.1 and Appendix A. Callers serialize events and perform returned actions;
// the package owns no timers, goroutines, locks, or transport resources.
package watchdog

// State is the peer control block's Status in RFC 3539 Appendix A.
type State string

const (
	Initial State = "INITIAL"
	Okay    State = "OKAY"
	Suspect State = "SUSPECT"
	Down    State = "DOWN"
	Reopen  State = "REOPEN"
)

// Event describes an admitted input. ReceiveDWA means a response credited by
// the caller's validation policy; message decoding and correlation stay there.
type Event uint8

const (
	ConnectionUp Event = iota
	ConnectionDown
	Expired
	Receive
	ReceiveDWA
)

// Machine is the RFC 3539 Appendix A peer control block, excluding its timer.
// A signed NumDWA preserves the -1 sentinel after a missed recovery response.
type Machine struct {
	State   State
	Pending bool
	NumDWA  int
}

// Actions are obligations of the caller, not operations performed by Step.
// Reset requests a fresh Tw while connected; an owner of a disconnected peer
// supplies its reconnect policy. Discard applies to application traffic; the
// caller still handles transport protocol control messages as required.
type Actions struct {
	Send, Reset, Failover, Failback, Close, Open, Discard bool
}

// Step returns a candidate control block and its actions without changing m.
// Commit a Send transition only after publication succeeds and a ReceiveDWA
// transition only after validation succeeds. Terminal transport cleanup may
// release Pending; Step itself follows the Appendix A table literally.
func (m Machine) Step(event Event) (Machine, Actions) {
	var a Actions
	switch event {
	case Receive, ReceiveDWA:
		// RFC 3539 Appendix A OnReceive: only DWA clears Pending.
		if event == ReceiveDWA {
			m.Pending = false
		}
		switch m.State {
		case Okay:
			a.Reset = true
		case Suspect:
			m.State = Okay
			a.Failback, a.Reset = true, true
		case Reopen:
			if event == ReceiveDWA {
				m.NumDWA++
				if m.NumDWA == 3 {
					m.State, a.Failback = Okay, true
				}
			} else {
				a.Discard = true
			}
		case Initial, Down:
			a.Discard = true
		}
	case Expired:
		// RFC 3539 Appendix A OnTimerElapsed: never retransmit a Pending DWR.
		a.Reset = true
		switch m.State {
		case Okay:
			if !m.Pending {
				m.Pending, a.Send = true, true
			} else {
				m.State, a.Failover = Suspect, true
			}
		case Suspect:
			m.State, a.Close = Down, true
		case Initial, Down:
			a.Open = true
		case Reopen:
			if !m.Pending {
				m.Pending, a.Send = true, true
			} else if m.NumDWA < 0 {
				m.State, a.Close = Down, true
			} else {
				m.NumDWA = -1
			}
		}
	case ConnectionUp:
		// RFC 3539 §3.4.1 [5], Appendix A OnConnectionUp: only recovery probes.
		switch m.State {
		case Initial:
			m.State, a.Reset = Okay, true
		case Down:
			m.State, m.NumDWA, m.Pending = Reopen, 0, true
			a.Send, a.Reset = true, true
		}
	case ConnectionDown:
		// RFC 3539 Appendix A's connection-down table uses the OLD status for
		// Failover. Its preceding pseudocode assigns DOWN before switching.
		previous := m.State
		m.State, a.Close = Down, true
		switch previous {
		case Okay, Suspect, Reopen:
			a.Failover, a.Reset = previous == Okay, true
		}
	}
	return m, a
}
