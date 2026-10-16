package sm

import (
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type clientRetryGateConn struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *clientRetryGateConn) Write(b []byte) (int, error) {
	if h, err := diam.DecodeHeader(b); err == nil && h.CommandCode == 0xeeff {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Write(b)
}

// RFC 6733 §§5.3,6.2.1: a matching CEA completes the exchange even when
// an already selected CER retry is waiting for the native publication gate.
func TestClientQueuedCERRetryStopsAfterCEA(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		t.Cleanup(unblock)
		opened := make(chan diam.Conn, 1)
		handshake := make(chan struct{})
		cli := newLivenessClient(t)
		cli.EnableWatchdog = false
		cli.MaxRetransmits = 3
		cli.RetransmitInterval = time.Minute
		cli.Handler.cfg.HostIPAddresses = []datatype.Address{{Family: datatype.AddressFamilyIPv4, Value: []byte{127, 0, 0, 1}}}
		cli.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
		cli.Handler.cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { opened <- e.Conn }
		cli.Handler.cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { close(handshake) }
		raw, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
		p := &protocolClientWire{client: cli, peer: peer, dialed: make(chan protocolClientDialResult, 1)}
		dialDone := make(chan struct{})
		go func() {
			defer close(dialDone)
			conn, err := cli.NewConn(&clientRetryGateConn{Conn: raw, entered: entered, release: release}, "synthetic.example")
			p.dialed <- protocolClientDialResult{conn: conn, err: err}
		}()
		var err error
		p.cer, err = diam.ReadMessage(peer, cli.Dict)
		if err != nil {
			t.Fatal(err)
		}
		stray := protocolClientCEA(p.cer, diam.Success)
		stray.Header.HopByHopID++
		p.send(t, stray)
		var conn diam.Conn
		select {
		case conn = <-opened:
		case <-time.After(10 * time.Second):
			t.Fatal("stray CEA did not expose its deciding connection")
		}
		written := make(chan error, 1)
		go func() { _, err := diam.NewRequest(0xeeff, 4, cli.Dict).WriteTo(conn); written <- err }()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("application writer did not hold the native gate")
		}
		var state *acceptedHandshake
		cli.Handler.cores.Range(func(_, value any) bool { state = value.(*acceptedHandshake); return false })
		if state == nil {
			t.Fatal("CER did not select a connection core")
		}

		t.Cleanup(func() {
			unblock()
			_ = peer.Close()
			_ = raw.Close()
			state.apply(protocol.Input{Kind: protocol.Abort})
			<-dialDone
		})
		synctest.Wait()
		time.Sleep(cli.RetransmitInterval)
		synctest.Wait()
		// All I/O in this exchange uses bubble-owned channels. Quiescence
		// after writer selection proves the retry is blocked at the held gate.
		state.mu.Lock()
		selected := len(state.writes) == 1
		controls := state.core.Snapshot().Controls()
		state.mu.Unlock()
		if len(controls) != 1 || controls[0].Command != diam.CapabilitiesExchange || controls[0].Writers != 1 || !selected {
			t.Fatal("CER retry did not reach the held publication gate")
		}
		p.send(t, protocolClientCEA(p.cer, diam.Success))
		select {
		case <-handshake:
		case <-time.After(10 * time.Second):
			t.Fatal("CEA callback did not complete")
		}
		result := p.dialResult(t)
		if result.err != nil || result.conn == nil {
			t.Fatalf("NewConn=%+v", result)
		}
		t.Cleanup(result.conn.Close)
		synctest.Wait()
		state.mu.Lock()
		remaining := len(state.writes)
		state.mu.Unlock()
		if remaining != 0 || len(state.snapshot().Controls()) != 0 {
			t.Fatal("answered CER retry remained blocked behind the native gate")
		}
		unblock()
		frame, err := diam.ReadMessage(peer, cli.Dict)
		if err != nil || frame.Header.CommandCode != 0xeeff {
			t.Fatalf("application frame=%v error=%v", frame, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if n, err := peer.Read(b[:]); n != 0 {
			t.Fatalf("completed CER retry published %d extra bytes", n)
		} else {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("connection did not remain open: %v", err)
			}
		}
	})
}
