package middleware

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm"
)

func tracerStateMachineConn(t *testing.T, timeout time.Duration) (net.Conn, *sm.Settings, *lockedBuffer) {
	t.Helper()
	settings := &sm.Settings{OriginHost: "traced.server.example", OriginRealm: "server.example", ProductName: "traced-server", AcctApplicationID: []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1))}, HandshakeTimeout: timeout}
	state, err := sm.New(settings)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	srv := &diam.Server{Handler: NewTracer(state), Dict: dict.Default, Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	c, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c, settings, logs
}

func malformedTracedDWR(t *testing.T) (*diam.Message, []byte) {
	t.Helper()
	m := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	m.Header.CommandFlags |= diam.ProxiableFlag | diam.RetransmittedFlag
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wire[1], wire[2], wire[3] = 0, 0, diam.HeaderLength+8
	return m, append(wire, 0, 0, 1, 2, avp.Mbit, 0xff, 0xff, 0xff)
}

func TestTracerStateMachineAnswersMalformedRequest(t *testing.T) {
	c, settings, _ := tracerStateMachineConn(t, time.Second)
	if _, err := sendCER(c); err != nil {
		t.Fatal(err)
	}
	cea, err := diam.ReadMessage(c, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := cea.FindAVP(avp.ResultCode, 0); err != nil || a.Data != datatype.Unsigned32(diam.Success) {
		t.Fatalf("handshake result=%v, %v", a, err)
	}
	request, wire := malformedTracedDWR(t)
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(c, dict.Default)
	if err != nil {
		t.Fatalf("traced state machine did not answer malformed request: %v", err)
	}
	// RFC 6733 §§7.1.5, 7.2: 5014 is a permanent failure, not an E-bit
	// protocol error. §7.5 and Verified Erratum 4615 require one Failed-AVP.
	if h := answer.Header; h.ApplicationID != request.Header.ApplicationID || h.CommandCode != request.Header.CommandCode || h.HopByHopID != request.Header.HopByHopID || h.EndToEndID != request.Header.EndToEndID || h.CommandFlags&(diam.RequestFlag|diam.ErrorFlag|diam.RetransmittedFlag) != 0 {
		t.Fatalf("answer header=%+v, request=%+v", h, request.Header)
	}
	if a, err := answer.FindAVP(avp.ResultCode, 0); err != nil || a.Data != datatype.Unsigned32(diam.InvalidAVPLength) {
		t.Fatalf("error result=%v, %v", a, err)
	}
	for code, want := range map[uint32]datatype.DiameterIdentity{avp.OriginHost: settings.OriginHost, avp.OriginRealm: settings.OriginRealm} {
		// RFC 6733 §7.2 and Verified Erratum 4887: locally created answers
		// contain the responder's identity, including Origin-Realm.
		a, err := answer.FindAVP(code, 0)
		if err != nil || a.Data != want {
			t.Fatalf("identity %d=%v, want %v (%v)", code, a, want, err)
		}
	}
	failed := 0
	for _, a := range answer.AVP {
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			failed++
			group, ok := a.Data.(*diam.GroupedAVP)
			if !ok || len(group.AVP) != 1 || group.AVP[0].Code != avp.AuthApplicationID {
				t.Fatalf("Failed-AVP=%v", a)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("Failed-AVP count=%d, want 1", failed)
	}
	dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("cli")))
	dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("localhost")))
	if _, err := dwr.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	dwa, err := diam.ReadMessage(c, dict.Default)
	if err != nil {
		t.Fatalf("connection did not continue after 5014: %v", err)
	}
	if dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID {
		t.Fatalf("DWA header=%+v", dwa.Header)
	}
	if a, err := dwa.FindAVP(avp.ResultCode, 0); err != nil || a.Data != datatype.Unsigned32(diam.Success) {
		t.Fatalf("DWA result=%v, %v", a, err)
	}
}

func TestTracerStateMachineRejectsMalformedBeforeCER(t *testing.T) {
	c, _, logs := tracerStateMachineConn(t, time.Second)
	_, wire := malformedTracedDWR(t)
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	// RFC 6733 §5.6.1: no non-CER request is admitted before capability
	// exchange, even when optional interfaces are reached through middleware.
	if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("pre-CER response=(%d,%v), want no answer and EOF", n, err)
	}
	// No wait: the component deciding to close must record before the close.
	if got := logs.String(); !strings.Contains(got, "level=WARN") || !strings.Contains(got, "sm:") || !strings.Contains(got, "closing connection") {
		t.Fatalf("close decision absent at EOF:\n%s", got)
	}
}

func TestTracerStateMachineHandshakeTimeout(t *testing.T) {
	c, _, logs := tracerStateMachineConn(t, 20*time.Millisecond)
	var b [1]byte
	if _, err := c.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("handshake timeout did not close traced connection: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, "sm:") || !strings.Contains(got, "closing connection") {
		t.Fatalf("timeout decision absent at EOF:\n%s", got)
	}
}
