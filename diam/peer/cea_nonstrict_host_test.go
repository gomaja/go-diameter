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
)

func TestManagerRejectsNonStrictMalformedCEAHostIPAddress(t *testing.T) {
	// RFC 6733 §§5.3.2 and 7.1.5: a malformed CEA ends the exchange.
	p := dict.New(dict.Base, dict.CreditControl)
	p.SetStrict(false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	bad := []byte{255, 255, 1}
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		request, err := diam.ReadMessage(conn, p)
		if err != nil {
			serverErr <- err
			return
		}
		answer := request.Answer(diam.Success)
		answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("remote.example.net")))
		answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
		answer.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Unknown(bad)))
		answer.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
		if _, err := answer.WriteTo(conn); err != nil {
			serverErr <- err
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		followup, err := diam.ReadMessage(conn, p)
		if err == nil {
			serverErr <- errors.New("peer answered malformed CEA: " + followup.String())
			return
		}
		if !errors.Is(err, io.EOF) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	settings := testSettings("local.example.net")
	settings.Dict = p
	events := make(chan PeerEvent, 16)
	manager, err := New(Config{Settings: settings, OnPeerEvent: func(event PeerEvent) { events <- event }})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager, nil)
	if err := manager.AddPeer(PeerConfig{Host: "remote.example.net", Endpoints: []Endpoint{{Network: "tcp", Address: listener.Addr().String()}}, NoAutoReconnect: true}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case report := <-events:
			var messageErr *diam.MessageError
			if !errors.As(report.Reason, &messageErr) {
				continue
			}
			if messageErr.ResultCode != diam.InvalidAVPValue || !strings.Contains(report.Reason.Error(), "CEA") {
				t.Fatalf("peer event = %T(%v), want CEA MessageError 5004", report.Reason, report.Reason)
			}
			if messageErr.FailedAVP == nil || messageErr.FailedAVP.Code != avp.HostIPAddress || !bytes.Equal(messageErr.FailedAVP.Data.Serialize(), bad) {
				t.Fatalf("FailedAVP = %v, want Host-IP-Address %x", messageErr.FailedAVP, bad)
			}
			goto reported
		case <-deadline:
			t.Fatal("missing peer error report")
		}
	}
reported:
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}
