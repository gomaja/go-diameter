package sm

import (
	"bytes"
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

func TestClientRejectsNonStrictMalformedCEAHostIPAddress(t *testing.T) {
	// RFC 6733 §§5.3.2 and 7.1.5: report the offending CEA AVP locally.
	p := dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf)
	p.SetStrict(false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverErr := make(chan error, 1)
	bad := []byte{255, 255, 1}
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
			serverErr <- errors.New("client answered malformed CEA: " + followup.String())
			return
		}
		if !errors.Is(err, io.EOF) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	client := &Client{Dict: p, Handler: mustNewStateMachine(t, clientSettings), AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}}
	conn, err := client.Dial(listener.Addr().String())
	if conn != nil {
		conn.Close()
		t.Fatal("accepted malformed CEA")
	}
	var messageErr *diam.MessageError
	if !errors.As(err, &messageErr) || messageErr.ResultCode != diam.InvalidAVPValue || !strings.Contains(err.Error(), "CEA") {
		t.Fatalf("Dial error = %T(%v), want CEA MessageError 5004", err, err)
	}
	if messageErr.FailedAVP == nil || messageErr.FailedAVP.Code != avp.HostIPAddress || !bytes.Equal(messageErr.FailedAVP.Data.Serialize(), bad) {
		t.Fatalf("FailedAVP = %v, want Host-IP-Address %x", messageErr.FailedAVP, bad)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}
