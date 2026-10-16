package peer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

type detachedAnswerWire struct {
	*coreActivityWire
	records *logtest.Recorder
	peers   chan PeerEvent
}

func newDetachedAnswerWire(t *testing.T, dialed bool) *detachedAnswerWire {
	t.Helper()
	p := &detachedAnswerWire{coreActivityWire: &coreActivityWire{clock: &fakeClock{}, events: make(chan diam.ProtocolErrorEvent, 32), dialed: dialed}, records: logtest.New(), peers: make(chan PeerEvent, 64)}
	settings := testSettings("local.example.net")
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { p.events <- e }
	var err error
	p.m, err = New(Config{Settings: settings, Logger: p.records.Logger(), Clock: p.clock, OnPeerEvent: func(e PeerEvent) { p.peers <- e }, Timers: Timers{TwInit: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	peer := PeerConfig{Host: "known.example.net", NoAutoReconnect: true}
	var srv *diam.Server
	if dialed {
		p.listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.listener.Close() })
		peer.Endpoints = []Endpoint{{Network: "tcp", Address: p.listener.Addr().String()}}
	}
	if err = p.m.AddPeer(peer); err != nil {
		t.Fatal(err)
	}
	if dialed {
		if err = p.m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else {
		p.listener, srv = startReceiverWithHandlers(t, p.m, 8)
	}
	t.Cleanup(func() {
		if p.c != nil {
			_ = p.c.Close()
		}
		closeManager(t, p.m, srv)
	})
	p.connect(t)
	return p
}

// Hold the actor while the native TCP handler admits an answer through ingress.
// Taking and replacing the already-enqueued events observes that admission;
// no protocol event is processed by the test and the actor remains the executor.
func detachedAnswerQueued(t *testing.T, p *detachedAnswerWire, answer *diam.Message, release chan struct{}) event {
	t.Helper()
	write(t, p.c, answer)
	var queued []event
	for {
		select {
		case e := <-p.a.events:
			queued = append(queued, e)
			if e.kind == wireEvent && e.s == p.s && e.msg.Header.CommandCode == answer.Header.CommandCode {
				if e.delivery == nil || e.receiveSequence == 0 {
					t.Fatal("TCP answer bypassed ordered ingress")
				}
				t.Logf("ingress answer command=%d application=%d hop=%08x end=%08x sequence=%d received_at=%s", e.msg.Header.CommandCode, e.msg.Header.ApplicationID, e.msg.Header.HopByHopID, e.msg.Header.EndToEndID, e.receiveSequence, e.receivedAt.UTC().Format(time.RFC3339Nano))
				for _, held := range queued {
					p.a.events <- held
				}
				return e
			}
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("TCP answer did not reach the actor queue")
			return event{}
		}
	}
}

const detachedAnswerWarning = "peer: answer on retired connection generation (RFC 6733 §6.2.1)"

func detachedAnswerWarnings(p *detachedAnswerWire) []slog.Record {
	var found []slog.Record
	for _, r := range p.records.Records() {
		if fmt.Sprint(logtest.Attr(r, "error").Any()) == detachedAnswerWarning {
			found = append(found, r)
		}
	}
	return found
}
func detachedAnswerPeerBarrier(t *testing.T, p *detachedAnswerWire) []PeerEvent {
	t.Helper()
	marker := errors.New("peer observer completion")
	p.m.notify(PeerEvent{Reason: marker})
	var found []PeerEvent
	for {
		select {
		case e := <-p.peers:
			if e.Reason == marker {
				return found
			}
			if e.Reason != nil && e.Reason.Error() == detachedAnswerWarning {
				found = append(found, e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("peer observer did not finish diagnostics")
			return nil
		}
	}
}

// A local failure or disconnect timeout detaches the session after the answer has
// entered ingress. The queued answer can report its stale generation, but may
// neither complete the old request successfully nor restore the closed peer.
func TestManagerDetachedQueuedAnswerReportsStaleGenerationTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, closing := range []string{"local-failure", "local-DPR", "received-DPR"} {
			t.Run(fmt.Sprintf("dialed=%t/%s", dialed, closing), func(t *testing.T) {
				p := newDetachedAnswerWire(t, dialed)
				request, result := closingPending(t, p.m, p.c)
				switch closing {
				case "local-DPR":
					p.a.post(event{kind: stop})
					if request := read(t, p.c); request.Header.CommandCode != diam.DisconnectPeer {
						t.Fatal("local stop did not send DPR")
					}
					awaitState(t, p.m, Closing)
				case "received-DPR":
					closingStart(t, p.m, p.c, false, diam.UnableToComply)
				}
				actorDeliveryFence(t, p.a)
				entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var beforePhase protocol.Phase
				p.a.post(event{testHook: func() {
					close(entered)
					<-release
					if closing == "local-failure" {
						p.a.failLocal("receive", io.ErrClosedPipe)
					} else {
						p.a.handle(event{kind: timeout})
					}
					beforePhase = p.s.protocolSnapshot().Phase()
					t.Logf("local close committed at=%s phase=%v", time.Now().UTC().Format(time.RFC3339Nano), beforePhase)
					close(closed)
				}})
				actorDeliveryWait(t, entered, "actor gate")
				answer := request.Answer(diam.Success)
				queued := detachedAnswerQueued(t, p, answer, release)
				close(release)
				actorDeliveryWait(t, closed, "local timeout")
				actorDeliveryWait(t, queued.delivery.done, "detached answer decision")
				actorDeliveryFence(t, p.a)
				var got sendResult
				select {
				case got = <-result:
				case <-time.After(5 * time.Second):
					t.Fatal("local close did not finish pending request")
				}
				if !errors.Is(got.err, ErrFailover) || got.answer != nil {
					t.Fatalf("queued detached answer completed the request: %+v", got)
				}
				if p.m.Peers()[0].State != Closed || p.m.Peers()[0].Eligible || beforePhase != protocol.Closed || p.s.protocolSnapshot().Phase() != beforePhase {
					t.Fatal("detached answer revived closed state")
				}
				logs := detachedAnswerWarnings(p)
				if len(logs) != 1 {
					t.Fatalf("detached application answer stale-generation warnings=%d; want one", len(logs))
				}
				record := logs[0]
				if record.Level != slog.LevelWarn || record.Message != "peer: protocol error" || fmt.Sprintf("%T", logtest.Attr(record, "error").Any()) != "*errors.errorString" || logtest.Attr(record, "message.command_code").Uint64() != 272 {
					t.Fatalf("stale-generation diagnostic changed: %+v", record)
				}
				var notice diam.ProtocolErrorEvent
				for notice.Err == nil || notice.Err.Kind() != diam.ProtocolUnexpectedMessage {
					select {
					case notice = <-p.events:
					case <-time.After(5 * time.Second):
						t.Fatal("detached answer lost ProtocolUnexpectedMessage")
					}
				}
				expected := *answer.Header
				expected.MessageLength = uint32(answer.Len())
				protocolErrorCheck(t, notice, p.s.c, expected, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0, 0)
				peers := detachedAnswerPeerBarrier(t, p)
				if len(peers) != 1 || peers[0].Peer.State != Closed || peers[0].Peer.Eligible || fmt.Sprintf("%T", peers[0].Reason) != "*errors.errorString" {
					t.Fatalf("stale-generation peer reasons=%+v", peers)
				}
			})
		}
	}
}

func TestManagerRetiredQueuedAnswerRemainsSilentTCP(t *testing.T) {
	p := newDetachedAnswerWire(t, false)
	request, result := closingPending(t, p.m, p.c)
	actorDeliveryFence(t, p.a)
	entered, release := make(chan struct{}), make(chan struct{})
	p.a.post(event{testHook: func() { close(entered); <-release }})
	actorDeliveryWait(t, entered, "actor gate")
	queued := detachedAnswerQueued(t, p, request.Answer(diam.Success), release)
	retired := make(chan error, 1)
	go func() { retired <- p.m.HandleRetire(p.s.c, diam.SCTPAssociationRestart) }()
	// The dedicated mailbox has accepted the real retirement before the actor
	// resumes. Its priority over ordinary events seals this generation first.
	var command retirementCommand
	select {
	case command = <-p.a.control:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("retirement did not enter its mailbox")
	}
	p.a.control <- command
	close(release)
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retirement did not complete")
	}
	actorDeliveryWait(t, queued.delivery.done, "retired answer disposition")
	actorDeliveryFence(t, p.a)
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrFailover) || got.answer != nil {
			t.Fatalf("retired answer completed pending request: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retirement did not finish pending request")
	}
	if !p.s.isRetired() || p.s.protocolSnapshot().Phase() != protocol.Retired || p.m.Peers()[0].State != Closed {
		t.Fatal("retired answer changed generation state")
	}
	if len(detachedAnswerWarnings(p)) != 0 || len(detachedAnswerPeerBarrier(t, p)) != 0 {
		t.Fatal("retired answer produced ordinary stale-generation diagnostics")
	}
	select {
	case e := <-p.events:
		t.Fatalf("retired answer generated protocol event: %+v", e)
	default:
	}
}
