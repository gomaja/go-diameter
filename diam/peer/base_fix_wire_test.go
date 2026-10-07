package peer

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// RFC 6733 §§6.2 and 7.1.5: Manager shares the error-answer builder;
// undecodable Session-Id must not prevent the 5014 answer.
func TestFixManagerAnswersTCP(t *testing.T) {
	t.Run("length7", func(t *testing.T) {
		settings := testSettings("local.example.net")
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
		cer, err := base.BuildCER(dict.Default, testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		write(t, conn, cer)
		if a := read(t, conn); code(t, a) != diam.Success {
			t.Fatal(a)
		}
		r := diam.NewMessage(diam.SessionTermination, diam.RequestFlag|diam.ProxiableFlag, 0, 0x12345678, 0x87654321, dict.Default)
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
