package sm

import (
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
)

const correlationTw = 150 * time.Millisecond

func newWatchdogCorrelationWire(t *testing.T, mode string, events chan acceptedWatchdogEvent) *protocolWire {
	t.Helper()
	onEvent := func(c diam.Conn, event WatchdogEvent) {
		events <- acceptedWatchdogEvent{conn: c, event: event}
	}
	if mode == "accepted" {
		p := newProtocolWire(t, func(cfg *Settings) {
			cfg.EnableWatchdog = true
			cfg.WatchdogInterval = correlationTw
			cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
			cfg.OnWatchdogConnEvent = onEvent
		}, false)
		p.send(t, regressionCER(t, p.conn.Dictionary(), 1001))
		if cea, err := diam.ReadMessage(p.peer, p.conn.Dictionary()); err != nil || !testResultCode(cea, diam.Success) {
			t.Fatalf("CEA = %v, %v", cea, err)
		}
		return p
	}
	p := newProtocolClientWire(t, func(cli *Client) {
		cli.EnableWatchdog = true
		cli.WatchdogInterval = correlationTw
		cli.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		cli.OnWatchdogConnEvent = onEvent
	})
	cea := protocolClientCEA(p.cer, diam.Success)
	setWireIdentity(t, cea, avp.OriginHost, string(clientSettings.OriginHost))
	setWireIdentity(t, cea, avp.OriginRealm, string(clientSettings.OriginRealm))
	p.send(t, cea)
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
