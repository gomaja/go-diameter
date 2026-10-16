package peer_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
)

// BenchmarkInboundMessages uses only public Manager APIs and real TCP sockets.
// Manager has no inbound application handler: requests receive 3001, while
// unsolicited answers complete at the synchronous protocol-error observer.
// CorrelatedApplicationAnswer measures the complete Send request/answer exchange,
// including the outbound request, correlation and the peer's response encoding.
// WatchdogExchange measures an inbound DWR and its outbound DWA. Automatic local
// address discovery remains enabled. Setup, CER/CEA and one warmup are untimed.
func BenchmarkInboundMessages(b *testing.B) {
	for _, side := range []string{"Accepted", "Dialed"} {
		b.Run(side, func(b *testing.B) {
			for _, exchange := range []string{"ApplicationRequestRejection", "UnsolicitedApplicationAnswer", "CorrelatedApplicationAnswer", "WatchdogExchange"} {
				b.Run(exchange, func(b *testing.B) { benchmarkInboundMessages(b, side, exchange) })
			}
		})
	}
}

func benchmarkInboundMessages(b *testing.B, side, exchange string) {
	dictionary, err := dict.New(dict.Base(), creditcontrol.Dictionary())
	if err != nil {
		b.Fatal(err)
	}
	notifications := make(chan diam.ProtocolErrorEvent, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := peer.New(peer.Config{
		Settings: sm.Settings{OriginHost: "local.example", OriginRealm: "example", VendorID: 13,
			ProductName: "benchmark", Dict: dictionary,
			AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))},
			OnProtocolError:   func(e diam.ProtocolErrorEvent) { notifications <- e },
		},
		Timers: peer.Timers{TwInit: time.Hour}, Logger: logger,
	})
	if err != nil {
		b.Fatal(err)
	}
	remote := messageCostPeer(b, manager, dictionary, logger, side)
	request := diam.NewMessage(diam.ReAuth, diam.RequestFlag|diam.ProxiableFlag, 4, 3, 4, dictionary)
	request.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("benchmark;1")))
	host, destination := "peer.example", "local.example"
	if exchange == "CorrelatedApplicationAnswer" {
		host, destination = destination, host
	}
	addMessageCostIdentity(request, host)
	request.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	request.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(destination)))
	request.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	request.AddAVP(diam.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Enumerated(0)))
	message := request
	switch exchange {
	case "UnsolicitedApplicationAnswer":
		message = request.Answer(diam.Success)
		message.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("benchmark;1")))
		addMessageCostIdentity(message, "peer.example")
	case "WatchdogExchange":
		message = diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 3, 4, dictionary)
		addMessageCostIdentity(message, "peer.example")
	}
	wire, err := message.Serialize()
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var responderDone chan error
	if exchange == "CorrelatedApplicationAnswer" {
		responderDone = make(chan error, 1)
		go func() {
			for {
				incoming, err := diam.ReadMessage(remote, dictionary)
				if err != nil {
					responderDone <- err
					return
				}
				answer := incoming.Answer(diam.Success)
				answer.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("benchmark;1")))
				addMessageCostIdentity(answer, "peer.example")
				if _, err := answer.WriteTo(remote); err != nil {
					responderDone <- err
					return
				}
			}
		}()
		defer func() { _ = remote.Close(); <-responderDone }()
	}
	exchangeMessage := func() {
		if exchange == "CorrelatedApplicationAnswer" {
			answer, err := manager.Send(ctx, request)
			if err != nil {
				b.Fatal(err)
			}
			messageCostResult(b, answer, diam.Success)
			if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.CommandFlags&diam.RequestFlag != 0 {
				b.Fatalf("unexpected correlated answer: %+v", answer.Header)
			}
			return
		}
		if n, err := remote.Write(wire); err != nil || n != len(wire) {
			b.Fatalf("write = %d, %v; want %d bytes", n, err, len(wire))
		}
		if exchange != "UnsolicitedApplicationAnswer" {
			answer, err := diam.ReadMessage(remote, dictionary)
			if err != nil {
				b.Fatal(err)
			}
			if answer.Header.CommandCode != message.Header.CommandCode || answer.Header.CommandFlags&diam.RequestFlag != 0 ||
				answer.Header.HopByHopID != message.Header.HopByHopID || answer.Header.EndToEndID != message.Header.EndToEndID {
				b.Fatalf("unexpected answer: %+v", answer.Header)
			}
			result := uint32(diam.Success)
			if exchange == "ApplicationRequestRejection" {
				result = diam.CommandUnsupported
			}
			messageCostResult(b, answer, result)
		}
		if exchange == "ApplicationRequestRejection" || exchange == "UnsolicitedApplicationAnswer" {
			select {
			case event := <-notifications:
				if !event.Message.HasHeader || event.Message.Header.CommandCode != message.Header.CommandCode ||
					event.Message.Header.HopByHopID != message.Header.HopByHopID || event.Message.Header.EndToEndID != message.Header.EndToEndID {
					b.Fatalf("unexpected protocol notification: %+v", event)
				}
			case <-ctx.Done():
				b.Fatal("protocol notification: ", ctx.Err())
			}
		}
	}
	exchangeMessage()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		exchangeMessage()
	}
	b.StopTimer()
}

func messageCostResult(b *testing.B, message *diam.Message, want uint32) {
	b.Helper()
	result, err := message.FindAVP(avp.ResultCode, 0)
	if err != nil || result.Data != datatype.Unsigned32(want) {
		b.Fatalf("Result-Code = %v, %v; want %d", result, err, want)
	}
}

func messageCostPeer(b *testing.B, manager *peer.Manager, dictionary *dict.Parser, logger *slog.Logger, side string) net.Conn {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	config := peer.PeerConfig{Host: "peer.example", NoAutoReconnect: true}
	if side == "Dialed" {
		config.Endpoints = []peer.Endpoint{{Network: "tcp", Address: listener.Addr().String()}}
	}
	if err := manager.AddPeer(config); err != nil {
		b.Fatal(err)
	}
	var server *diam.Server
	var served chan error
	if side == "Accepted" {
		server = &diam.Server{Dict: dictionary, Logger: logger}
		if err := manager.BindServer(server); err != nil {
			b.Fatal(err)
		}
		served = make(chan error, 1)
		go func() { served <- server.Serve(listener) }()
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx, sm.DisconnectDoNotWantToTalkToYou); err != nil {
			b.Error(err)
		}
		if server != nil {
			if err := server.Close(); err != nil && !errors.Is(err, diam.ErrServerClosed) {
				b.Error(err)
			}
			if err := <-served; err != nil && !errors.Is(err, diam.ErrServerClosed) {
				b.Error(err)
			}
		}
	})
	if err := manager.Start(context.Background()); err != nil {
		b.Fatal(err)
	}
	var remote net.Conn
	if side == "Accepted" {
		remote, err = net.Dial("tcp", listener.Addr().String())
	} else {
		if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			b.Fatal(err)
		}
		remote, err = listener.Accept()
	}
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = remote.Close() })
	if err := remote.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	if side == "Accepted" {
		cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dictionary)
		addMessageCostCapabilities(cer)
		if _, err := cer.WriteTo(remote); err != nil {
			b.Fatal(err)
		}
		cea, err := diam.ReadMessage(remote, dictionary)
		if err != nil {
			b.Fatal(err)
		}
		if cea.Header.CommandCode != diam.CapabilitiesExchange || cea.Header.CommandFlags&diam.RequestFlag != 0 {
			b.Fatalf("CEA = %+v", cea.Header)
		}
		messageCostResult(b, cea, diam.Success)
	} else {
		cer, err := diam.ReadMessage(remote, dictionary)
		if err != nil {
			b.Fatal(err)
		}
		if cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
			b.Fatalf("CER = %+v", cer.Header)
		}
		cea := cer.Answer(diam.Success)
		addMessageCostCapabilities(cea)
		if _, err := cea.WriteTo(remote); err != nil {
			b.Fatal(err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		snapshots := manager.Peers()
		if len(snapshots) == 1 && snapshots[0].Eligible {
			break
		}
		if time.Now().After(deadline) {
			b.Fatalf("peer never became eligible: %+v", snapshots)
		}
		time.Sleep(time.Millisecond)
	}
	return remote
}

func addMessageCostIdentity(message *diam.Message, host string) {
	message.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(host)))
	message.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
}

func addMessageCostCapabilities(message *diam.Message) {
	addMessageCostIdentity(message, "peer.example")
	message.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))))
	message.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13)))
	message.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("benchmark")))
	message.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
}
