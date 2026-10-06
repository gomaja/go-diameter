package sm

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// Handshake writes and closes can be paused after their externally visible effect.
type handshakeConn struct {
	*messageErrorCaptureConn
	mu         sync.Mutex
	ctx        context.Context
	writes     chan []byte
	afterWrite func()
	afterClose func()
	closed     atomic.Bool
	writeErr   error
}

func newHandshakeConn() *handshakeConn {
	return &handshakeConn{messageErrorCaptureConn: &messageErrorCaptureConn{}, ctx: context.Background(), writes: make(chan []byte, 4)}
}
func (c *handshakeConn) Context() context.Context       { c.mu.Lock(); defer c.mu.Unlock(); return c.ctx }
func (c *handshakeConn) SetContext(ctx context.Context) { c.mu.Lock(); c.ctx = ctx; c.mu.Unlock() }
func (c *handshakeConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes <- append([]byte(nil), b...)
	if c.afterWrite != nil {
		c.afterWrite()
	}
	return len(b), nil
}
func (c *handshakeConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }
func (c *handshakeConn) Close() {
	first := c.closed.CompareAndSwap(false, true)
	if first && c.afterClose != nil {
		c.afterClose()
	}
}
func regressionDWR(t *testing.T) *diam.Message {
	t.Helper()
	m := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	return m
}

func TestAcceptedHandshakePublishedBeforeCEA(t *testing.T) {
	t.Run("blocked-write", func(t *testing.T) {
		sm := New(testMessageErrorSettings())
		c := newHandshakeConn()
		release := make(chan struct{})
		var writes atomic.Int32
		c.afterWrite = func() {
			if writes.Add(1) == 1 {
				<-release
			}
		}
		cleanup := sm.HandleAccept(c)
		defer cleanup()
		cer := regressionCER(t, dict.Default, 1001)
		done := make(chan struct{})
		go func() { defer close(done); sm.ServeDIAM(c, cer) }()
		defer func() { close(release); <-done }()
		select {
		case <-c.writes:
		case <-time.After(2 * time.Second):
			t.Fatal("CEA not written")
		}
		sm.ServeDIAM(c, regressionDWR(t))
		if c.closed.Load() {
			t.Fatal("DWR after CEA closed the connection")
		}
		select {
		case wire := <-c.writes:
			answer, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil || answer.Header.CommandCode != diam.DeviceWatchdog || !testResultCode(answer, diam.Success) {
				t.Fatalf("DWA = %v, %v", answer, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("DWR after CEA was not answered")
		}
	})
	t.Run("concurrent-loopback", func(t *testing.T) {
		srv := diamtest.NewUnstartedServer(New(testMessageErrorSettings()), dict.Default)
		srv.Config.MaxConcurrentHandlers = -1
		srv.Start()
		defer srv.Close()
		cer, dwr := regressionCER(t, dict.Default, 1001), regressionDWR(t)
		for i := 0; i < 300; i++ {
			func() {
				c, err := net.DialTimeout("tcp", srv.Addr, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				for _, req := range []*diam.Message{cer, dwr} {
					if _, err = req.WriteTo(c); err != nil {
						t.Fatal(err)
					}
					answer, err := diam.ReadMessage(c, dict.Default)
					if err != nil || answer.Header.CommandCode != req.Header.CommandCode || !testResultCode(answer, diam.Success) {
						t.Fatalf("exchange %d, command %d: answer=%v err=%v", i, req.Header.CommandCode, answer, err)
					}
				}
			}()
		}
		t.Log("300 concurrent-dispatch CER/CEA/DWR/DWA exchanges completed without drops")
	})
}

func TestCERWriteFailureClosesConnection(t *testing.T) {
	sm := New(testMessageErrorSettings())
	c := newHandshakeConn()
	c.writeErr = errors.New("CEA write failed")
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
	if !c.closed.Load() {
		t.Fatal("failed CEA write left the connection open")
	}
}

func TestExpiredHandshakeCannotSendSuccessCEA(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.HandshakeTimeout = 100 * time.Millisecond
	var onCEACalls int
	settings.OnCEA = func(diam.Conn, *diam.Message) { onCEACalls++ }
	sm := New(settings)
	c := newHandshakeConn()
	closing, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c.afterClose = func() { close(closing); <-release; close(done) }
	cleanup := sm.HandleAccept(c)
	defer cleanup()
	defer func() { close(release); <-done }()
	select {
	case <-closing:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake timer did not close")
	}
	sm.ServeDIAM(c, regressionCER(t, dict.Default, 1001))
	select {
	case <-c.writes:
		t.Fatal("expired handshake sent a success CEA")
	default:
	}
	if onCEACalls != 0 {
		t.Fatalf("OnCEA ran %d times for a CEA that was not sent", onCEACalls)
	}
	if _, ok := smpeer.FromContext(c.Context()); ok {
		t.Fatal("expired handshake left peer metadata on the connection context")
	}
}

func TestCERNilSettingsDictionaryUsesMessageDictionary(t *testing.T) {
	dictionary, err := dict.NewParser("../dict/testdata/base.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err = dictionary.Load(bytes.NewBufferString(`<diameter><application id="16777999" name="Private"><auth/></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	settings := testMessageErrorSettings()
	settings.Dict = nil
	srv := diamtest.NewServer(New(settings), dictionary)
	defer srv.Close()
	request := regressionCER(t, dictionary, 1001)
	for _, a := range request.AVP {
		if a.Code == avp.AcctApplicationID {
			a.Code = avp.AuthApplicationID
			a.Data = datatype.Unsigned32(16777999)
		}
	}
	answer, _ := regressionExchange(t, srv, request, dictionary)
	if !testResultCode(answer, diam.Success) {
		result, _ := answer.FindAVP(avp.ResultCode, 0)
		t.Fatalf("nil Settings.Dict: Result-Code=%v, want 2001", result.Data)
	}
}
