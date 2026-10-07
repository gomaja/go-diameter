package diam

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/testutil"
)

func TestMessageStreamSCTP(t *testing.T) {
	for index, tc := range []struct {
		name  string
		depth int
		reset bool
		read  uint
		want  uint
	}{
		{"direct", 0, false, 3, 7},
		{"one", 1, false, 3, 7},
		{"two", 2, false, 3, 7},
		{"opaque", -1, false, 3, 7},
		{"reset-read", 0, true, 3, 3},
		{"reset-default", 0, true, InvalidStreamID, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := MultistreamListen("sctp", "127.0.0.1:0")
			if err != nil {
				t.Skipf("SCTP unavailable: %v", err)
			}
			defer func() { _ = l.Close() }()
			type accepted struct {
				c   net.Conn
				err error
			}
			acceptedc := make(chan accepted, 1)
			go func() { c, err := l.Accept(); acceptedc <- accepted{c, err} }()
			client, err := getMultistreamDialer("sctp", testutil.SCTPTimeout, nil).Dial("sctp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			var peer net.Conn
			select {
			case a := <-acceptedc:
				if a.err != nil {
					t.Fatal(a.err)
				}
				peer = a.c
			case <-time.After(testutil.SCTPTimeout):
				t.Fatal("accept timed out")
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetReadDeadline(time.Now().Add(testutil.SCTPTimeout)); err != nil {
				t.Fatal(err)
			}
			transport := client.(*SCTPConn)
			transport.SetCurrentStream(tc.read)
			response := (&Server{}).newConn(transport).writer
			var c Conn = response
			for range tc.depth {
				c = unwrapConn{c}
			}
			if tc.depth < 0 {
				c = opaqueConn{c}
			}
			m, err := ReadMessage(bytes.NewReader(testMessage), nil)
			if err != nil {
				t.Fatal(err)
			}
			m.Header.HopByHopID = 0x5200 + uint32(index)
			m.Header.EndToEndID = 0x5300 + uint32(index)
			payload, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if tc.reset {
				response.SetWriterStream(7)
				response.ResetWriterStream()
				_, err = response.Write(payload)
			} else {
				_, err = m.WriteToStream(c, 7)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(payload)+64)
			n, got, err := peer.(*SCTPConn).ReadAny(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b[:n], payload) {
				t.Fatal("SCTP payload changed")
			}
			if got != tc.want {
				t.Fatalf("stream = %d, want %d", got, tc.want)
			}
		})
	}
}
