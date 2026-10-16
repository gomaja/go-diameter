package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

type heldCEAWriteConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *heldCEAWriteConn) Write(b []byte) (int, error) {
	if len(b) >= 20 && b[4]&diam.RequestFlag == 0 && uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7]) == diam.CapabilitiesExchange {
		c.once.Do(func() { close(c.entered) })
		<-c.release
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

type heldCEAWriteListener struct {
	net.Listener
	entered chan struct{}
	release <-chan struct{}
}

func (l *heldCEAWriteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &heldCEAWriteConn{Conn: c, entered: l.entered, release: l.release}, nil
}

func actorDeliveryWait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
func actorDeliveryFence(t *testing.T, a *actor) {
	t.Helper()
	done := make(chan struct{})
	go func() { a.commit(event{}, newProtocolDelivery()); close(done) }()
	actorDeliveryWait(t, done, "actor completion")
}

// The CEA is accepted by the session queue and reaches a real transport write
// before its controlled failure. Election completion is an actor-owned event;
// its delivery must remain usable even when admission generated no notices.
func TestManagerElectionCEAWriteFailureNotifiesTCP(t *testing.T) {
	for _, loss := range []string{"dial-failure", "initiator-loss"} {
		t.Run(loss, func(t *testing.T) {
			releaseDial := make(chan struct{})
			var dialOnce sync.Once
			unblockDial := func() { dialOnce.Do(func() { close(releaseDial) }) }
			releaseWrite := make(chan struct{})
			var writeOnce sync.Once
			unblockWrite := func() { writeOnce.Do(func() { close(releaseWrite) }) }
			releaseObserver := make(chan struct{})
			var observerOnce sync.Once
			unblockObserver := func() { observerOnce.Do(func() { close(releaseObserver) }) }
			t.Cleanup(unblockDial)
			t.Cleanup(unblockWrite)
			t.Cleanup(unblockObserver)
			enteredWrite, enteredObserver := make(chan struct{}), make(chan struct{})
			events := make(chan diam.ProtocolErrorEvent, 8)
			settings := testSettings("aaa.example.net")
			settings.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				events <- e
				if e.Reply == diam.ProtocolReplyFailed {
					close(enteredObserver)
					<-releaseObserver
				}
			}
			cfg := Config{Settings: settings, Clock: &fakeClock{}}
			endpoint := Endpoint{Network: "tcp", Address: "127.0.0.1:1"}
			var outgoing net.Listener
			var initiator net.Conn
			if loss == "dial-failure" {
				cfg.Dial = func(ctx context.Context, _ Endpoint) (net.Conn, error) {
					select {
					case <-releaseDial:
						return nil, errors.New("outbound dial failed")
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			} else {
				var err error
				outgoing, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = outgoing.Close() })
				_ = outgoing.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
				endpoint.Address = outgoing.Addr().String()
			}
			m, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.AddPeer(PeerConfig{Host: "known.example.net", NoAutoReconnect: true, Endpoints: []Endpoint{endpoint}}); err != nil {
				t.Fatal(err)
			}
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := &heldCEAWriteListener{Listener: raw, entered: enteredWrite, release: releaseWrite}
			srv := &diam.Server{Dict: m.dictionary(), MaxConcurrentHandlers: 8}
			if err = m.BindServer(srv); err != nil {
				t.Fatal(err)
			}
			go func() { _ = srv.Serve(listener) }()
			t.Cleanup(func() {
				unblockDial()
				unblockWrite()
				unblockObserver()
				if initiator != nil {
					_ = initiator.Close()
				}
				closeManager(t, m, srv)
			})
			if err = m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if loss == "initiator-loss" {
				initiator, err = outgoing.Accept()
				if err != nil {
					t.Fatal(err)
				}
				if cer := read(t, initiator); cer.Header.CommandCode != diam.CapabilitiesExchange {
					t.Fatal("initiator did not send CER")
				}
				awaitState(t, m, WaitICEA)
			} else {
				awaitState(t, m, WaitConnAck)
			}
			incoming, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = incoming.Close() })
			cer := capabilitiesExchangeRequest(t)
			write(t, incoming, cer)
			held := WaitConnAckElect
			if loss == "initiator-loss" {
				held = WaitReturns
			}
			awaitState(t, m, held)
			m.mu.RLock()
			a := m.peers["known.example.net"]
			m.mu.RUnlock()
			var responder *session
			a.commit(event{testHook: func() { responder = a.r }}, newProtocolDelivery())
			if responder == nil {
				t.Fatal("election lost its accepted candidate")
			}
			if loss == "dial-failure" {
				unblockDial()
			} else {
				_ = initiator.Close()
			}
			actorDeliveryWait(t, enteredWrite, "accepted CEA transport write")
			t.Logf("CEA write held before bytes command=%d hop=%08x end=%08x at=%s", cer.Header.CommandCode, cer.Header.HopByHopID, cer.Header.EndToEndID, time.Now().UTC().Format(time.RFC3339Nano))
			actorDeliveryFence(t, a)
			unblockWrite()
			actorDeliveryWait(t, enteredObserver, "required CEA failure observer")
			notice := <-events
			expected := *cer.Header
			expected.MessageLength = uint32(cer.Len())
			protocolErrorCheck(t, notice, responder.c, expected, diam.ProtocolReplyFailure, 0, true, diam.ProtocolReplyFailed, diam.Success, 0)
			// A blocked observer must not own the actor which selected the CEA.
			actorDeliveryFence(t, a)
			unblockObserver()
			correlationEOF(t, incoming)
			actorDeliveryFence(t, a)
			select {
			case extra := <-events:
				t.Fatalf("duplicate CEA failure notification: %+v", extra)
			default:
			}
		})
	}
}
