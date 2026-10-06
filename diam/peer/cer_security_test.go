package peer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestCERMalformedSecurityReturnsFailedAVP(t *testing.T) {
	dictionary, err := dict.NewParser("../dict/testdata/base.xml", "../dict/testdata/credit_control.xml")
	if err != nil {
		t.Fatal(err)
	}
	dictionary.Strict = false
	settings := testSettings("local.example.net")
	settings.Dict = dictionary
	m, err := New(Config{Settings: settings})
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
	srv := &diam.Server{Dict: dictionary}
	if err = m.BindServer(srv); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	defer closeManager(t, m, srv)
	c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cer, err := base.BuildCER(dictionary, testBase("known.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	malformed := diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{0, 1})
	cer.AddAVP(malformed)
	write(t, c, cer)
	if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(c, dictionary)
	if err != nil {
		t.Fatal(err)
	}
	if got := code(t, answer); got != diam.InvalidAVPLength {
		t.Fatalf("Result-Code=%d, want 5014", got)
	}
	expected, err := malformed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range answer.AVP {
		if a.Code != avp.FailedAVP {
			continue
		}
		count++
		// Failed-AVP members decode leniently (RFC 6733 §7.5), so the
		// malformed child keeps its received bytes.
		group, ok := a.Data.(*diam.GroupedAVP)
		if !ok || len(group.AVP) != 1 {
			t.Fatalf("Failed-AVP=%v, want one member", a)
		}
		child, err := group.AVP[0].Serialize()
		if err != nil || !bytes.Equal(child, expected) {
			t.Fatalf("Failed-AVP member=% x (%v), want malformed Inband-Security-Id % x", child, err, expected)
		}
	}
	if count != 1 || answer.Header.CommandFlags != 0 {
		t.Fatalf("Failed-AVP count=%d, flags=%#x", count, answer.Header.CommandFlags)
	}
	var b [1]byte
	_, err = c.Read(b[:])
	if err == nil {
		t.Fatal("rejected CER connection stayed open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("rejected CER connection did not close")
	}
}
