package sm

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

const correlationTw = 150 * time.Millisecond

func newWatchdogCorrelationWire(t *testing.T, mode string, events chan acceptedWatchdogEvent) *protocolWire {
	t.Helper()
	onEvent := func(c diam.Conn, event WatchdogEvent) {
		events <- acceptedWatchdogEvent{conn: c, event: event}
	}
	if mode == "accepted" {
		return newProtocolWire(t, func(cfg *Settings) {
			cfg.EnableWatchdog = true
			cfg.WatchdogInterval = correlationTw
			cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
			cfg.OnWatchdogConnEvent = onEvent
		}, true)
	}
	p := newProtocolClientWire(t, func(cli *Client) {
		cli.EnableWatchdog = true
		cli.WatchdogInterval = correlationTw
		cli.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		cli.OnWatchdogConnEvent = onEvent
	})
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	return &protocolWire{sm: p.client.Handler, peer: p.peer, conn: p.conn, events: p.events, logs: p.logs}
}

// RFC 6733 §§3, 6.2.1 and RFC 3539 §3.4.1, Appendix A: only the
// outstanding request's answer clears Pending. Removing either identifier
// comparison must make the corresponding case fail on both connection roles.
func TestWatchdogDWACorrelation(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		for _, scenario := range []string{"hop-by-hop", "end-to-end", "delayed-duplicate", "matching"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				events := make(chan acceptedWatchdogEvent, 32)
				p := newWatchdogCorrelationWire(t, mode, events)
				// Complete an earlier probe on this same connection, then hold A.
				earlier := acceptedWatchdogOnWire(t, p.peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
				p.send(t, acceptedDWA(t, earlier, diam.Success))
				awaitAcceptedEvent(t, events, WatchdogAnswerReceived, p.conn)
				request := acceptedWatchdogOnWire(t, p.peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
				if scenario != "matching" {
					answer := acceptedDWA(t, request, diam.Success)
					switch scenario {
					case "hop-by-hop":
						answer.Header.HopByHopID++
					case "end-to-end":
						answer.Header.EndToEndID++
					case "delayed-duplicate":
						answer = acceptedDWA(t, earlier, diam.Success)
					}
					header := p.send(t, answer)
					// A credited stray answer emits AnswerReceived and sends a new
					// DWR at Tw instead of becoming SUSPECT with A still pending.
					awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
					assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header,
						diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
					records := p.logs.RecordsWithMessage("sm: unhandled answer discarded")
					if len(records) != 1 || records[0].Level != slog.LevelWarn {
						t.Fatalf("unmatched DWA log records = %v, want one warning", records)
					}
				} else {
					awaitAcceptedEvent(t, events, WatchdogSuspect, p.conn)
				}
				// A matching answer still recovers SUSPECT and clears A. Generic
				// activity and answer processing may publish recovery in either order.
				p.send(t, acceptedDWA(t, request, diam.Success))
				seen := make(map[WatchdogEvent]bool)
				for range 2 {
					e := awaitCorrelationRecovery(t, events, p.conn)
					if seen[e] {
						t.Fatalf("duplicate recovery event %s", e)
					}
					seen[e] = true
				}
				acceptedWatchdogOnWire(t, p.peer)
				awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
				select {
				case e := <-p.events:
					t.Fatalf("extra protocol notification: %+v", e)
				default:
				}
			})
		}
	}
}

func awaitCorrelationRecovery(t *testing.T, events <-chan acceptedWatchdogEvent, conn diam.Conn) WatchdogEvent {
	t.Helper()
	select {
	case e := <-events:
		if e.conn != conn || e.event != WatchdogRecovered && e.event != WatchdogAnswerReceived {
			t.Fatalf("recovery event = (%p, %s), want matching DWA recovery on %p", e.conn, e.event, conn)
		}
		return e.event
	case <-time.After(2 * time.Second):
		t.Fatal("matching DWA did not recover the pending probe")
		return ""
	}
}

func TestWatchdogDWADuplicateWithoutPending(t *testing.T) {
	for _, mode := range []string{"accepted", "dialed"} {
		t.Run(mode, func(t *testing.T) {
			events := make(chan acceptedWatchdogEvent, 16)
			p := newWatchdogCorrelationWire(t, mode, events)
			request := acceptedWatchdogOnWire(t, p.peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
			p.send(t, acceptedDWA(t, request, diam.Success))
			awaitAcceptedEvent(t, events, WatchdogAnswerReceived, p.conn)
			header := p.send(t, acceptedDWA(t, request, diam.Success))
			acceptedWatchdogOnWire(t, p.peer)
			awaitAcceptedEvent(t, events, WatchdogRequestSent, p.conn)
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header,
				diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
		})
	}
}

type immediateDWAConn struct {
	*watchdogProbeConn
	onWrite func([]byte)
}

func (c *immediateDWAConn) WriteStream(wire []byte, _ uint) (int, error) {
	c.onWrite(wire)
	return len(wire), nil
}

// The peer can answer bytes that it has read before the writer returns.
// Moving identifier registration after WriteToStream must fail this test.
func TestPublishDWRRegistersBeforeWriteReturns(t *testing.T) {
	signals := newWatchdogSignals()
	c := &immediateDWAConn{watchdogProbeConn: newWatchdogProbeConn()}
	c.onWrite = func(wire []byte) {
		request, err := diam.ReadMessage(bytes.NewReader(wire), newSMTestDictionary(dict.Base()))
		if err != nil {
			t.Fatal(err)
		}
		kind, code := processDWA(c, acceptedDWA(t, request, diam.Success), &signals, nil)
		if kind != "" || code != 0 || len(signals.dwac) != 1 {
			t.Fatalf("immediate DWA = (%s, %d), acknowledgements = %d; request not registered before write", kind, code, len(signals.dwac))
		}
	}
	var events []WatchdogEvent
	if !publishDWR(c, regressionDWR(t), &signals, 0, new(sync.Mutex), nil,
		func(event WatchdogEvent) { events = append(events, event) }, nil) {
		t.Fatal("DWR publication failed")
	}
	if len(events) != 1 || events[0] != WatchdogRequestSent {
		t.Fatalf("publication events = %v", events)
	}
}

func TestWatchdogDWAConcurrentDuplicate(t *testing.T) {
	signals := newWatchdogSignals()
	logs := logtest.New()
	c := loggedWatchdogConn{Conn: newWatchdogProbeConn(), logger: logs.Logger()}
	request := regressionDWR(t)
	if !publishDWR(c, request, &signals, 0, new(sync.Mutex), nil, func(WatchdogEvent) {}, nil) {
		t.Fatal("DWR publication failed")
	}
	const copies = 16
	results := make(chan diam.ProtocolErrorKind, copies)
	answers := make([]*diam.Message, copies)
	for i := range answers {
		answers[i] = acceptedDWA(t, request, diam.Success)
	}
	start := make(chan struct{})
	for _, answer := range answers {
		go func() {
			<-start
			kind, _ := processDWA(c, answer, &signals, nil)
			results <- kind
		}()
	}
	close(start)
	credited := 0
	for range copies {
		switch kind := <-results; kind {
		case "":
			credited++
		case diam.ProtocolUnexpectedMessage:
		default:
			t.Fatalf("duplicate DWA result = %s", kind)
		}
	}
	if credited != 1 || len(signals.dwac) != 1 {
		t.Fatalf("duplicate DWAs credited = %d, queued = %d; want one", credited, len(signals.dwac))
	}
	if records := logs.RecordsWithMessage("sm: unhandled answer discarded"); len(records) != copies-1 {
		t.Fatalf("duplicate DWA warnings = %d, want %d", len(records), copies-1)
	}
}
