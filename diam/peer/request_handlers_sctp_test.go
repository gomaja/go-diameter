//go:build linux && !386

package peer_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-sctp"
)

func TestManagerRequestHandlersSCTPStream(t *testing.T) {
	for _, frontend := range parityFrontends {
		if !frontend.manager {
			continue
		}
		t.Run(frontend.name, func(t *testing.T) {
			h := fatalMessageManagerTransport(t, frontend, "sctp")
			transport, ok := h.wire.(diam.MultistreamConn)
			if !ok {
				// The accepted-Manager fixture dials its remote side directly
				// with go-sctp; adapt that side to retain received stream IDs.
				raw, ok := h.wire.(*sctp.Conn)
				if !ok {
					t.Fatalf("SCTP remote transport = %T", h.wire)
				}
				var err error
				transport, err = diam.NewSCTPConn(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			streams := make(chan uint, 1)
			writes := make(chan error, 1)
			h.manager.HandleIdx(diam.CommandIndex{AppID: contractApp, Code: contractCommand, Request: true}, diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
				streams <- request.MessageStream()
				writes <- requestHandlerReply(c, request)
			}))

			const stream = uint(3)
			request := requestHandlerRequest(h, 0x15303)
			if err := transport.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := request.WriteToStream(transport, stream); err != nil || n != request.Len() {
				t.Fatalf("request stream write = %d, %v; want %d bytes", n, err, request.Len())
			}
			want, err := requestHandlerAnswer(request).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			wire := make([]byte, len(want)+1)
			n, gotStream, err := transport.ReadAny(wire)
			if err != nil {
				t.Fatal(err)
			}
			if gotStream != stream {
				t.Fatalf("answer stream = %d; want %d", gotStream, stream)
			}
			if !bytes.Equal(wire[:n], want) {
				t.Fatalf("answer bytes = %x; want %x", wire[:n], want)
			}
			answer, err := diam.ReadMessage(bytes.NewReader(wire[:n]), h.dict)
			if err != nil {
				t.Fatal(err)
			}
			if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.CommandFlags != diam.ProxiableFlag ||
				answer.Header.ApplicationID != request.Header.ApplicationID || answer.Header.HopByHopID != request.Header.HopByHopID ||
				answer.Header.EndToEndID != request.Header.EndToEndID || contractCode(t, answer) != diam.Success {
				t.Fatalf("handler SCTP answer = %v", answer)
			}
			for _, field := range []struct {
				code uint32
				want any
			}{
				{avp.SessionID, contractField(t, request, avp.SessionID).Data},
				{avp.OriginHost, datatype.DiameterIdentity("local.example.net")},
				{avp.OriginRealm, datatype.DiameterIdentity("example.net")},
			} {
				if got := contractField(t, answer, field.code).Data; got != field.want {
					t.Fatalf("answer AVP %d = %v; want %v", field.code, got, field.want)
				}
			}
			if got := parityAwait(t, streams); got != stream {
				t.Fatalf("handler request stream = %d; want %d", got, stream)
			}
			if err := parityAwait(t, writes); err != nil {
				t.Fatal(err)
			}
			h.barrier(t)
			h.noEvents(t)
		})
	}
}
