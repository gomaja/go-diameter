package peer

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 6733 §§6.2 and 7.1.5: Manager shares the error-answer builder;
// undecodable Session-Id must not prevent the 5014 answer.
func TestManagerErrorAnswersOnWire(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	t.Run("length7", func(t *testing.T) {
		settings := testSettings("local.example.net", testDict)
		settings.RejectUnknownMandatoryAVPs = true
		m, err := New(Config{Settings: settings})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
			t.Fatal(err)
		}
		l, s := startReceiver(t, m)
		defer closeManager(t, m, s)
		conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		cer, err := base.BuildCER(testDict, testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		write(t, conn, cer)
		if a := read(t, conn); code(t, a) != diam.Success {
			t.Fatal(a)
		}
		r := diam.NewMessage(diam.SessionTermination, diam.RequestFlag|diam.ProxiableFlag, 0, 0x12345678, 0x87654321, testDict)
		expected := uint32(diam.InvalidAVPLength)
		offending := uint32(avp.SessionID)
		r.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("sid")))
		wire, err := r.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		wire[25], wire[26], wire[27] = 0, 0, 7
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
		a := read(t, conn)
		if code(t, a) != expected || a.Header.HopByHopID != r.Header.HopByHopID || a.Header.EndToEndID != r.Header.EndToEndID {
			t.Fatalf("answer: %v", a)
		}
		if len(a.FindAVPsWithPath(diam.AVPRef{Code: avp.SessionID})) != 0 {
			t.Fatal("invented Session-Id")
		}
		f := a.FindAVPsWithPath(diam.AVPRef{Code: avp.FailedAVP})
		if len(f) != 1 {
			t.Fatalf("Failed-AVP count %d", len(f))
		}
		g := f[0].Data.(*diam.GroupedAVP)
		if len(g.AVP) != 1 || g.AVP[0].Code != offending {
			t.Fatal("wrong evidence")
		}
		if err := a.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

// RFC 6733 §§7.1.3 and 7.2: an unknown peer receives a 3010 error answer,
// using the generic answer-message grammar, before its transport closes.
func TestUnknownPeerCEACarriesEBit(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	m, err := New(Config{Settings: testSettings("local.example.net", testDict)})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
		t.Fatal(err)
	}
	l, srv := startReceiver(t, m)
	t.Cleanup(func() { closeManager(t, m, srv) })
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cer, err := base.BuildCER(testDict, testBase("other.example.net"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, c, cer)
	cea := read(t, c)
	if got := code(t, cea); got != diam.UnknownPeer {
		t.Errorf("Result-Code=%d, want 3010", got)
	}
	if cea.Header.CommandFlags != diam.ErrorFlag {
		t.Errorf("CEA with Result-Code 3010 has header flags %#02x, want E (RFC 6733 §7.1.3)", cea.Header.CommandFlags)
	}
	if cea.Header.CommandCode != cer.Header.CommandCode || cea.Header.ApplicationID != 0 || cea.Header.HopByHopID != cer.Header.HopByHopID || cea.Header.EndToEndID != cer.Header.EndToEndID {
		t.Errorf("CEA header=%+v, request header=%+v", cea.Header, cer.Header)
	}
	// Pin the existing BuildErrorAnswer shape, including local identities
	// (RFC 6733 §6.2, Verified Erratum 4887), without CEA capability fields.
	wantCodes := []uint32{avp.OriginHost, avp.OriginRealm, avp.ResultCode}
	wantData := []datatype.Type{datatype.DiameterIdentity("local.example.net"), datatype.DiameterIdentity("example.net"), datatype.Unsigned32(diam.UnknownPeer)}
	if len(cea.AVP) != len(wantCodes) {
		t.Errorf("error answer AVP count=%d, want %d (RFC 6733 §7.2)", len(cea.AVP), len(wantCodes))
	} else {
		for i, a := range cea.AVP {
			if a.Code != wantCodes[i] || a.VendorID != 0 || a.Flags != avp.Mbit || a.Data != wantData[i] {
				t.Errorf("error answer AVP[%d]=%+v, want code=%d data=%v", i, a, wantCodes[i], wantData[i])
			}
		}
	}
	if err := cea.ValidateOutgoing(); err != nil {
		t.Errorf("error answer grammar: %v", err)
	}
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("connection did not close: read=%d error=%v, want EOF", n, err)
	}
}
