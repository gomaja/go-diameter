package sm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

type eofErrorObserver struct {
	inner *StateMachine
	calls atomic.Int32
}

func (h *eofErrorObserver) Unwrap() diam.Handler                   { return h.inner }
func (h *eofErrorObserver) ServeDIAM(c diam.Conn, m *diam.Message) { h.inner.ServeDIAM(c, m) }
func (h *eofErrorObserver) HandleMessageError(c diam.Conn, m *diam.Message, err *diam.MessageError) error {
	h.calls.Add(1)
	return h.inner.HandleMessageError(c, m, err)
}

// An AVP decoder's EOF is a payload failure, not an orderly transport close.
// RFC 6733 §§7.1.5, 7.2, 7.5 and Verified Erratum 4615 require the error answer.
func TestDecoderEOFGetsMessageErrorAnswer(t *testing.T) {
	original := datatype.Decoder[datatype.Unsigned32Type]
	if err := datatype.RegisterDecoder(datatype.Unsigned32Type, func(b []byte) (datatype.Type, error) {
		if len(b) != 0 {
			return original(b)
		}
		var n uint32
		err := binary.Read(bytes.NewReader(b), binary.BigEndian, &n)
		return datatype.Unsigned32(n), err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := datatype.RegisterDecoder(datatype.Unsigned32Type, original); err != nil {
			t.Error(err)
		}
	})
	records := logtest.New()
	settings := testMessageErrorSettings()
	observer := &eofErrorObserver{inner: mustNewStateMachine(t, settings)}
	srv := diamtest.NewUnstartedServer(observer, dict.Default)
	srv.Config.Logger = records.Logger()
	accepted := make(chan diam.Conn, 1)
	srv.Config.OnNewConnection = func(c diam.Conn) { accepted <- c }
	srv.Start()
	c, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	serverConn := <-accepted
	t.Cleanup(func() {
		_ = c.Close()
		serverConn.Close()
		srv.Close()
		select {
		case <-serverConn.(interface{ DispatchDone() <-chan struct{} }).DispatchDone():
		case <-time.After(3 * time.Second):
			t.Error("server dispatch did not finish")
		}
	})
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeValidSMErrorCER(t, c)
	if a, err := diam.ReadMessage(c, dict.Default); err != nil || !testResultCode(a, diam.Success) {
		t.Fatalf("handshake: %v %v", a, err)
	}
	m := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 0x11223344, 0x55667788, dict.Default)
	m.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown(nil)))
	if _, err := m.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	a, err := diam.ReadMessage(c, dict.Default)
	if err != nil {
		t.Fatalf("decoder EOF got no RFC 6733 §7 answer: %v", err)
	}
	if observer.calls.Load() != 1 {
		t.Fatalf("MessageError handler calls=%d", observer.calls.Load())
	}
	if !testResultCode(a, diam.InvalidAVPLength) || a.Header.CommandCode != diam.DeviceWatchdog || a.Header.ApplicationID != 0 || a.Header.CommandFlags != 0 || a.Header.HopByHopID != m.Header.HopByHopID || a.Header.EndToEndID != m.Header.EndToEndID {
		t.Fatalf("incorrect error answer: %v", a)
	}
	failed := 0
	for _, v := range a.AVP {
		if v.Code == avp.FailedAVP {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("Failed-AVP count=%d", failed)
	}
	for code, want := range map[uint32]datatype.DiameterIdentity{avp.OriginHost: settings.OriginHost, avp.OriginRealm: settings.OriginRealm} {
		v, err := a.FindAVP(code, 0)
		if err != nil || v.Data != want {
			t.Fatalf("local identity %d: %v %v", code, v, err)
		}
	}
	logs := records.Records()
	if len(logs) != 1 || logs[0].Level != slog.LevelWarn {
		t.Fatalf("decoder records=%v", logs)
	}
	var me *diam.MessageError
	cause, _ := logtest.Attr(logs[0], "error").Any().(error)
	if !errors.As(cause, &me) || !errors.Is(cause, io.EOF) || me.Fatal {
		t.Fatalf("decoder cause lost: %v", cause)
	}
	if _, err := regressionDWR(t).WriteTo(c); err != nil {
		t.Fatal(err)
	}
	if a, err := diam.ReadMessage(c, dict.Default); err != nil || !testResultCode(a, diam.Success) {
		t.Fatalf("next DWA: %v %v", a, err)
	}
}
