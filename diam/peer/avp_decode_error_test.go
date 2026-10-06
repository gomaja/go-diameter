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

func TestManagerPayloadErrorIncludesFailedAVP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    uint32
		payload []byte
		result  uint32
	}{
		{"5014", avp.InbandSecurityID, []byte{1, 2}, diam.InvalidAVPLength},
		{"5004", avp.HostIPAddress, []byte{255, 255, 1}, diam.InvalidAVPValue},
	} {
		for _, first := range []bool{false, true} {
			stage := "after CER"
			if first {
				stage = "CER"
			}
			t.Run(tc.name+"/"+stage, func(t *testing.T) {
				manager, err := New(Config{Settings: testSettings("local.example.net")})
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.AddPeer(PeerConfig{Host: "known.example.net"}); err != nil {
					t.Fatal(err)
				}
				listener, server := startReceiver(t, manager)
				defer closeManager(t, manager, server)
				conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				t.Logf("TCP peer %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
				request, err := base.BuildCER(dict.Default, testBase("known.example.net"))
				if err != nil {
					t.Fatal(err)
				}
				if !first {
					write(t, conn, request)
					if cea := read(t, conn); code(t, cea) != diam.Success {
						t.Fatalf("CEA = %v", cea)
					}
					request, err = base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
					if err != nil {
						t.Fatal(err)
					}
				}
				request.AddAVP(diam.NewAVP(tc.code, avp.Mbit, 0, datatype.Unknown(tc.payload)))
				write(t, conn, request)
				answer := read(t, conn)
				if code(t, answer) != tc.result || answer.Header.CommandFlags != 0 || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
					t.Fatalf("error answer = %v", answer)
				}
				var failed []*diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.FailedAVP {
						failed = append(failed, a)
					}
				}
				if len(failed) != 1 {
					t.Fatalf("Result-Code %d has %d Failed-AVP containers, want 1", tc.result, len(failed))
				}
				want, err := diam.NewAVP(tc.code, avp.Mbit, 0, datatype.Unknown(tc.payload)).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if got := failed[0].Data.Serialize(); !bytes.Equal(got, want) {
					t.Fatalf("Failed-AVP = %x, want %x", got, want)
				}
				if !first {
					dwr, err := base.BuildDWR(dict.Default, testBase("known.example.net"), 0)
					if err != nil {
						t.Fatal(err)
					}
					write(t, conn, dwr)
					if dwa := read(t, conn); code(t, dwa) != diam.Success || dwa.Header.HopByHopID != dwr.Header.HopByHopID {
						t.Fatalf("following DWA = %v", dwa)
					}
				}
			})
		}
	}
}
