package peer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestManagedSendPeerClosesAfterRequestTCP(t *testing.T) {
	for _, answerFirst := range []bool{true, false} {
		name := "without-answer"
		if answerFirst {
			name = "after-answer"
		}
		t.Run(name, func(t *testing.T) {
			settings := testSettings("server.example.net")
			serverSM := sm.New(&settings)
			serverSM.HandleIdx(diam.CommandIndex{AppID: 4, Code: 272, Request: true}, diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
				if answerFirst {
					answer := request.Answer(diam.Success)
					_, _ = answer.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("server.example.net"))
					_, _ = answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net"))
					_, _ = answer.WriteTo(c)
				}
				c.Close()
			}))
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &diam.Server{Handler: serverSM, Dict: dict.Default}
			go func() { _ = server.Serve(listener) }()
			defer func() { _ = server.Close() }()
			m, err := New(Config{Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			if err := m.AddPeer(PeerConfig{Host: "server.example.net", Endpoints: []Endpoint{{Address: listener.Addr().String()}}}); err != nil {
				t.Fatal(err)
			}
			if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"server.example.net"}}}); err != nil {
				t.Fatal(err)
			}
			if err := m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for !m.Peers()[0].Eligible && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !m.Peers()[0].Eligible {
				t.Fatalf("peer did not open: %+v", m.Peers())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			got, err := m.Send(ctx, outboundRequest("", "example.net"))
			if answerFirst {
				if err != nil || got == nil {
					t.Fatalf("answer before close = %v, %v", got, err)
				}
			} else if !errors.Is(err, ErrFailover) {
				t.Fatalf("close without answer = %v, %v", got, err)
			}
		})
	}
}

func TestManagedSendTCPToSMServer(t *testing.T) {
	settings := testSettings("server.example.net")
	serverSM := sm.New(&settings)
	serverSM.HandleIdx(diam.CommandIndex{AppID: 4, Code: 272, Request: true}, diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
		answer := request.Answer(diam.Success)
		_, _ = answer.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("server.example.net"))
		_, _ = answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net"))
		_, _ = answer.WriteTo(c)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &diam.Server{Handler: serverSM, Dict: dict.Default}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	if err := m.AddPeer(PeerConfig{Host: "server.example.net", Endpoints: []Endpoint{{Address: listener.Addr().String()}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"server.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !m.Peers()[0].Eligible && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.Peers()[0].Eligible {
		t.Fatalf("peer did not open: %+v", m.Peers())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answer, err := m.Send(ctx, outboundRequest("", "example.net"))
	if err != nil {
		t.Fatal(err)
	}
	if answer == nil || answer.Header.CommandCode != 272 || answer.Header.CommandFlags&diam.RetransmittedFlag != 0 {
		t.Fatalf("answer = %+v", answer)
	}
}
