package peer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type capabilityWireConn struct {
	*fakeConn
	wire chan []byte
}

func (c *capabilityWireConn) Write(b []byte) (int, error) {
	c.wire <- append([]byte(nil), b...)
	return len(b), nil
}
func (c *capabilityWireConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }

func TestQueuedCERPrecedesMalformedRequest(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
		t.Fatal(err)
	}
	c := &capabilityWireConn{fakeConn: newFakeConn(), wire: make(chan []byte, 8)}
	// Deliberately hold the dispatcher until both reader callbacks have run.
	s := &session{m: m, c: c, inbound: true, writes: make(chan writeRequest, 8), ingress: make(chan incoming, 8), closed: make(chan struct{})}
	m.sessions[c] = s
	defer func() { s.close(); m.unregister(s); closeManager(t, m, nil) }()
	cer, err := base.BuildCER(dict.Default, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	m.ServeDIAM(c, cer)
	req, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	failed := diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2})
	if err = m.HandleMessageError(c, req, &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: failed}); err != nil {
		t.Fatal(err)
	}
	// No timing assumptions: the pre-fix error callback has already closed c.
	select {
	case <-c.done:
		t.Fatal("malformed second message discarded the queued CER")
	default:
	}
	m.wg.Add(2)
	go s.writer()
	go s.dispatch()
	for i, want := range []uint32{diam.Success, diam.InvalidAVPLength} {
		select {
		case wire := <-c.wire:
			answer, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			if code(t, answer) != want {
				t.Fatalf("answer %d = %v, want %d", i, answer, want)
			}
			request := cer
			if i == 1 {
				request = req
			}
			if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
				t.Fatalf("answer %d mismatched request: %v", i, answer)
			}
			if i == 1 {
				count := 0
				for _, a := range answer.AVP {
					if a.Code == avp.FailedAVP {
						count++
						if !bytes.Equal(a.Data.Serialize(), mustCapabilityAVP(t, failed)) {
							t.Fatal("Failed-AVP lost original bytes")
						}
					}
				}
				if count != 1 {
					t.Fatalf("Failed-AVP count=%d", count)
				}
			}
		case <-time.After(time.Second):
			t.Fatalf("missing answer %d", i)
		}
	}
}
func mustCapabilityAVP(t *testing.T, a *diam.AVP) []byte {
	t.Helper()
	b, err := a.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Hold the CER callback open until the following decode error is delivered.
// Server's admission barrier must preserve its position without sequence gaps.
type delayedCapabilityHandler struct {
	*Manager
	release chan struct{}
}

func (h *delayedCapabilityHandler) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == diam.CapabilitiesExchange {
		<-h.release
	}
	h.Manager.ServeDIAM(c, m)
}
func (h *delayedCapabilityHandler) HandleMessageError(c diam.Conn, m *diam.Message, e *diam.MessageError) error {
	close(h.release)
	return h.Manager.HandleMessageError(c, m, e)
}

func TestCERAndMalformedRequestArrivalOrderOnWire(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &diam.Server{Dict: dict.Default}
	if err = m.BindServer(srv); err != nil {
		t.Fatal(err)
	}
	srv.Handler = &delayedCapabilityHandler{Manager: m, release: make(chan struct{})}
	srv.MaxConcurrentHandlers = -1
	go func() { _ = srv.Serve(listener) }()
	defer closeManager(t, m, srv)
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cer, err := base.BuildCER(dict.Default, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	failed := diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2})
	req.AddAVP(failed)
	write(t, c, cer)
	write(t, c, req)
	for i, want := range []uint32{diam.Success, diam.InvalidAVPLength} {
		answer := read(t, c)
		if code(t, answer) != want {
			t.Fatalf("answer %d = %v, want %d", i, answer, want)
		}
		if i == 1 {
			a, err := answer.FindAVP(avp.FailedAVP, 0)
			if err != nil || !bytes.Equal(a.Data.Serialize(), mustCapabilityAVP(t, failed)) {
				t.Fatalf("Failed-AVP=%v, err=%v", a, err)
			}
		}
	}
	next, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, next)
	answer := read(t, c)
	if code(t, answer) != diam.Success || answer.Header.HopByHopID != next.Header.HopByHopID {
		t.Fatalf("post-error DWA=%v", answer)
	}
}

func TestManagerRejectsNonCEAOnWire(t *testing.T) {
	for _, kind := range []string{"CER", "DWR", "DWA", "application", "malformed-DWR", "malformed-CEA", "wrong-app-CEA"} {
		t.Run(kind, func(t *testing.T) {
			local, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			m, err := New(Config{Settings: testSettings("local.example.net"), Timers: Timers{CER: time.Minute}, Dial: func(context.Context, Endpoint) (net.Conn, error) { return local, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			if err = m.AddPeer(PeerConfig{Host: "known.example.net", Endpoints: []Endpoint{{Network: "tcp", Address: "127.0.0.1:3868"}}, NoAutoReconnect: true}); err != nil {
				t.Fatal(err)
			}
			if err = m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = remote.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			cer, err := diam.ReadMessage(remote, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			var msg *diam.Message
			switch kind {
			case "CER":
				msg, err = base.BuildCER(dict.Default, testBase("known.example.net"))
			case "DWR", "malformed-DWR":
				msg, err = base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
			case "DWA":
				msg = diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default).Answer(diam.Success)
			case "application":
				msg = diam.NewRequest(999999, 4, dict.Default)
			default:
				msg = cer.Answer(diam.Success)
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(kind, "malformed-") {
				msg.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			}
			if kind == "wrong-app-CEA" {
				msg.Header.ApplicationID = 4
			}
			if _, err = msg.WriteTo(remote); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			n, err := remote.Read(b[:])
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("expected immediate close without answer, got n=%d err=%v", n, err)
			}
		})
	}
}
