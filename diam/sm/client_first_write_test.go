package sm

import (
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

type clientPublishedCERFailureConn struct {
	net.Conn
	first   atomic.Bool
	release <-chan struct{}
	failure error
}

func (c *clientPublishedCERFailureConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && c.first.CompareAndSwap(false, true) {
		<-c.release
		return n, c.failure
	}
	return n, err
}

// RFC 6733 §5.3: receiving CEA can race the initial CER writer's return.
// NewConn retains its synchronous transport-error boundary in either order.
func TestClientFirstCERWriteErrorAfterSuccessfulCEA(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	admitted := make(chan struct{})
	failure := &net.OpError{Op: "write", Net: "tcp", Err: errors.New("synthetic first CER writer failure")}
	p := newClientCoreTCPDial(t, func(c *Client) {
		c.Handler.HandleFunc("ALL", func(diam.Conn, *diam.Message) { close(admitted) })
	}, func(c *Client, addr string) (diam.Conn, error) {
		rw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return c.NewConn(&clientPublishedCERFailureConn{Conn: rw, release: release, failure: failure}, addr)
	})
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	// An application callback proves production completed CEA admission and
	// queued the successful handshake result while the initial writer is held.
	// The callback performs no write that could wait behind that writer.
	p.send(t, diam.NewRequest(999, 4, p.client.Dict))
	select {
	case <-admitted:
	case <-time.After(10 * time.Second):
		t.Fatal("application callback did not follow accepted CEA")
	}
	unblock()
	result := p.dialResult(t)
	if result.conn != nil {
		defer result.conn.Close()
	}
	var transportErr *net.OpError
	if result.conn != nil || !errors.Is(result.err, failure) || !errors.As(result.err, &transportErr) {
		t.Fatalf("initial CER write error lost after accepted CEA: conn=%v err=%v", result.conn, result.err)
	}
}

// reflect.Type metadata in an exported wrapper is immutable. It must not
// prevent the public Client error path from retaining that wrapper's type.
func TestClientHandshakeRetainsJSONMarshalerError(t *testing.T) {
	p := newClientCoreTCP(t, nil)
	var conn diam.Conn
	p.client.Handler.cores.Range(func(key, _ any) bool { conn = key.(diam.Conn); return false })
	if conn == nil {
		t.Fatal("CER was sent without a connection core")
	}
	cause := errors.New("synthetic decoder failure")
	original := &json.MarshalerError{Type: reflect.TypeOf(int(0)), Err: cause}
	if err := p.client.Handler.HandleMessageError(conn, p.cer.Answer(diam.Success), &diam.MessageError{ResultCode: diam.InvalidAVPLength, Err: original}); err != nil {
		t.Fatal(err)
	}
	result := p.dialResult(t)
	var copied *json.MarshalerError
	if !errors.As(result.err, &copied) || copied.Type != original.Type || !errors.Is(result.err, cause) {
		t.Fatalf("public Dial lost concrete wrapper: %T %v", result.err, result.err)
	}
}

// RFC 6733 §§5.5.2,6.3: each logged rejection exposes its validation
// cause, protocol notification and public watchdog event.
func TestClientDWALogCauseCompatibilityTCP(t *testing.T) {
	for _, fault := range []string{"rejected", "host", "realm"} {
		t.Run(fault, func(t *testing.T) {
			p := newClientCoreTCP(t, func(c *Client) {
				c.EnableWatchdog = true
				c.WatchdogInterval = 200 * time.Millisecond
				c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
			})
			admitClientCoreTCP(t, p)
			probe := acceptedWatchdogOnWire(t, p.peer)
			code := uint32(diam.Success)
			if fault == "rejected" {
				code = diam.UnableToComply
			}
			m := acceptedDWA(t, probe, code)
			setWireIdentity(t, m, avp.OriginHost, "peer.example")
			setWireIdentity(t, m, avp.OriginRealm, "example")
			want := "DWA Result-Code 5012"
			if fault == "host" {
				setWireIdentity(t, m, avp.OriginHost, "wrong.example")
				want = "DWA Origin-Host mismatch"
			}
			if fault == "realm" {
				setWireIdentity(t, m, avp.OriginRealm, "wrong.example")
				want = "DWA Origin-Realm mismatch"
			}
			p.send(t, m)
			_ = protocolEvent(t, p.events)
			records := p.logs.Records()
			if len(records) != 1 || logError(records[0]) == nil || logError(records[0]).Error() != want {
				t.Fatalf("DWA original log cause lost: logs=%v want=%q", records, want)
			}
		})
	}
}

// RFC 6733 §§3,5.3.2: CEA header validation retains its distinct observer
// classification while the log and Dial expose the same validation error.
func TestClientCEAInvalidHeaderCompatibilityTCP(t *testing.T) {
	p := newClientCoreTCP(t, nil)
	m := protocolClientCEA(p.cer, diam.Success)
	m.Header.CommandFlags |= diam.ProxiableFlag
	header := p.send(t, m)
	event := protocolEvent(t, p.events)
	if event.Conn == nil {
		t.Fatal("CEA rejection lost its connection")
	}
	assertProtocolEvent(t, event, event.Conn, &header, diam.ProtocolInvalidHeader, diam.InvalidHDRBits, true, diam.ProtocolReplyNone, 0)
	result := p.dialResult(t)
	var returned *diam.MessageError
	if result.conn != nil || !errors.As(result.err, &returned) || returned.ResultCode != diam.InvalidHDRBits {
		t.Fatalf("invalid CEA header Dial=%+v", result)
	}
	records := p.logs.Records()
	if len(records) != 1 || records[0].Message != "sm: CEA rejected; closing connection" {
		t.Fatalf("invalid CEA header log=%v", records)
	}
	var logged *diam.MessageError
	if !errors.As(logError(records[0]), &logged) || logged.ResultCode != diam.InvalidHDRBits {
		t.Fatalf("invalid CEA header log lost original error: %T %v", logError(records[0]), logError(records[0]))
	}
}

type clientHeldApplicationWriteConn struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
}

func (c *clientHeldApplicationWriteConn) Write(b []byte) (int, error) {
	if len(b) >= diam.HeaderLength && uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7]) == 999 {
		close(c.entered)
		<-c.release
	}
	return c.Conn.Write(b)
}

// RFC 6733 §§3,5.3,6.2.1 and #109's answered-CER-retry rule: completion
// cancels an unpublished retry even while an unrelated native writer holds
// the physical gate. Cancellation still releases the core's writer pin.
func TestClientAnsweredCERReleasesQueuedRetryTCP(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	entered := make(chan struct{})
	p := newClientCoreTCPDial(t, func(c *Client) {
		c.MaxRetransmits = 1
		c.RetransmitInterval = time.Hour
	}, func(c *Client, addr string) (diam.Conn, error) {
		rw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return c.NewConn(&clientHeldApplicationWriteConn{Conn: rw, entered: entered, release: release}, addr)
	})
	var state *acceptedHandshake
	p.client.Handler.cores.Range(func(_, value any) bool { state = value.(*acceptedHandshake); return false })
	if state == nil {
		t.Fatal("CER was sent without a connection core")
	}
	gateDone := make(chan error, 1)
	go func() {
		_, err := diam.NewMessage(999, 0, 4, 1, 2, p.client.Dict).WriteTo(state.conn)
		gateDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("unrelated writer did not occupy the native gate")
	}
	timer := state.snapshot().Timer(protocol.RetryTimer)
	deadline := time.Now().Add(10 * time.Second)
	for timer.Token == 0 {
		if time.Now().After(deadline) {
			t.Fatal("initial CER did not arm its retransmission interval")
		}
		runtime.Gosched()
		timer = state.snapshot().Timer(protocol.RetryTimer)
	}
	retryDone := make(chan struct{})
	go func() {
		state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.RetryTimer, Token: timer.Token, At: timer.Deadline})
		close(retryDone)
	}()
	deadline = time.Now().Add(10 * time.Second)
	for {
		selected := false
		for _, control := range state.snapshot().Controls() {
			selected = selected || control.Command == diam.CapabilitiesExchange && control.Writers != 0
		}
		if selected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core did not select its CER retry")
		}
		runtime.Gosched()
	}
	admitClientCoreTCP(t, p)
	select {
	case <-retryDone:
	case <-time.After(10 * time.Second):
		t.Fatal("answered CER retry remained blocked behind the native writer gate")
	}
	state.mu.Lock()
	remaining := len(state.writes)
	state.mu.Unlock()
	if remaining != 0 || len(state.snapshot().Controls()) != 0 || p.conn.Closed() {
		t.Fatalf("cancelled CER retry retained ownership or closed the connection: tickets=%d snapshot=%+v", remaining, state.snapshot())
	}
	unblock()
	if err := <-gateDone; err != nil {
		t.Fatal(err)
	}
	application, err := diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || application.Header.CommandCode != 999 {
		t.Fatalf("unrelated writer frame=%v error=%v", application, err)
	}
	if err := p.peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	retry, err := diam.ReadMessage(p.peer, p.client.Dict)
	var timeout net.Error
	if retry != nil || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("answered CER retry appeared on wire: %v error=%v", retry, err)
	}
}
