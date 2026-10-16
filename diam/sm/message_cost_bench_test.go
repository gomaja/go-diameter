package sm_test

import (
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
	"github.com/gomaja/go-diameter/diam/sm"
)

// BenchmarkInboundMessages measures an admitted connection through the public
// server and client APIs. Automatic address discovery remains enabled. Each
// operation waits for its response or handler before starting the next message.
func BenchmarkInboundMessages(b *testing.B) {
	for _, side := range []string{"Accepted", "Dialed"} {
		b.Run(side, func(b *testing.B) {
			for _, exchange := range []string{"ApplicationRequest", "ApplicationAnswer", "WatchdogExchange"} {
				b.Run(exchange, func(b *testing.B) { benchmarkInboundMessages(b, side, exchange) })
			}
		})
	}
}

// BenchmarkCloseNotifyMessages measures a caller that explicitly retains early
// peer-loss notification while exchanging application and watchdog messages.
func BenchmarkCloseNotifyMessages(b *testing.B) {
	for _, exchange := range []string{"ApplicationRequest", "ApplicationAnswer", "WatchdogExchange"} {
		b.Run(exchange, func(b *testing.B) { benchmarkInboundMessages(b, "DialedCloseNotify", exchange) })
	}
}

func benchmarkInboundMessages(b *testing.B, side, exchange string) {
	dictionary, err := dict.New(dict.Base(), creditcontrol.Dictionary())
	if err != nil {
		b.Fatal(err)
	}
	machine, err := sm.New(&sm.Settings{
		OriginHost: "local.example", OriginRealm: "example", VendorID: 13,
		ProductName: "benchmark", Dict: dictionary,
		AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))},
		EnableWatchdog:    true, WatchdogInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	delivered := make(chan struct{}, 1)
	writeErrors := make(chan error, 1)
	machine.HandleFunc("RAR", func(c diam.Conn, m *diam.Message) {
		answer := m.Answer(diam.Success)
		answer.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("benchmark;1")))
		addMessageCostIdentity(answer, "local.example")
		if _, err := answer.WriteTo(c); err != nil {
			writeErrors <- err
		}
	})
	machine.HandleFunc("RAA", func(_ diam.Conn, _ *diam.Message) { delivered <- struct{}{} })
	peer := messageCostPeer(b, machine, dictionary, side)
	message := diam.NewMessage(diam.ReAuth, diam.RequestFlag|diam.ProxiableFlag, 4, 3, 4, dictionary)
	message.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("benchmark;1")))
	addMessageCostIdentity(message, "peer.example")
	message.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	message.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("local.example")))
	message.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	message.AddAVP(diam.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Enumerated(0)))
	switch exchange {
	case "ApplicationAnswer":
		message = message.Answer(diam.Success)
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
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	// Warm the admitted path before measurement, including lazy reader buffers.
	exchangeMessage := func() {
		if n, err := peer.Write(wire); err != nil || n != len(wire) {
			b.Fatalf("write = %d, %v; want %d bytes", n, err, len(wire))
		}
		if exchange == "ApplicationAnswer" {
			select {
			case <-delivered:
			case <-deadline.C:
				b.Fatal("application answer was not dispatched")
			}
			return
		}
		answer, err := diam.ReadMessage(peer, dictionary)
		if err != nil {
			select {
			case writeErr := <-writeErrors:
				b.Fatalf("handler write: %v; peer read: %v", writeErr, err)
			default:
				b.Fatal(err)
			}
		}
		if answer.Header.CommandCode != message.Header.CommandCode || answer.Header.CommandFlags&diam.RequestFlag != 0 ||
			answer.Header.HopByHopID != message.Header.HopByHopID || answer.Header.EndToEndID != message.Header.EndToEndID {
			b.Fatalf("unexpected answer header: %+v", answer.Header)
		}
		result, err := answer.FindAVP(avp.ResultCode, 0)
		if err != nil || result.Data != datatype.Unsigned32(diam.Success) {
			b.Fatalf("answer Result-Code = %v, %v; want success", result, err)
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

func messageCostPeer(b *testing.B, machine *sm.StateMachine, dictionary *dict.Parser, side string) net.Conn {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var peer net.Conn
	if side == "Accepted" {
		server := &diam.Server{Handler: machine, Dict: dictionary, Logger: logger}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		b.Cleanup(func() {
			if err := server.Close(); err != nil && !errors.Is(err, diam.ErrServerClosed) {
				b.Error(err)
			}
			if err := <-done; err != nil && !errors.Is(err, diam.ErrServerClosed) {
				b.Error(err)
			}
		})
		peer, err = net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = peer.Close() })
		messageCostDeadline(b, peer)
		cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dictionary)
		addMessageCostCapabilities(cer)
		if _, err := cer.WriteTo(peer); err != nil {
			b.Fatal(err)
		}
		cea, err := diam.ReadMessage(peer, dictionary)
		if err != nil || cea.Header.CommandCode != diam.CapabilitiesExchange || cea.Header.CommandFlags&diam.RequestFlag != 0 {
			b.Fatalf("CEA = %v, %v", cea, err)
		}
	} else {
		client := &sm.Client{Handler: machine, Dict: dictionary, Logger: logger,
			EnableWatchdog: true, WatchdogInterval: time.Hour, RetransmitInterval: time.Second}
		type dialResult struct {
			conn diam.Conn
			err  error
		}
		dialed := make(chan dialResult, 1)
		go func() { c, err := client.Dial(listener.Addr().String()); dialed <- dialResult{c, err} }()
		peer, err = listener.Accept()
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = peer.Close() })
		messageCostDeadline(b, peer)
		cer, err := diam.ReadMessage(peer, dictionary)
		if err != nil || cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
			b.Fatalf("CER = %v, %v", cer, err)
		}
		cea := cer.Answer(diam.Success)
		addMessageCostCapabilities(cea)
		if _, err := cea.WriteTo(peer); err != nil {
			b.Fatal(err)
		}
		result := <-dialed
		if result.err != nil {
			b.Fatal(result.err)
		}
		b.Cleanup(result.conn.Close)
		if side == "DialedCloseNotify" {
			result.conn.(diam.CloseNotifier).CloseNotify()
		}
	}
	return peer
}

func messageCostDeadline(b *testing.B, peer net.Conn) {
	b.Helper()
	if err := peer.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
}

func addMessageCostIdentity(message *diam.Message, host string) {
	message.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(host)))
	message.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
}

func addMessageCostCapabilities(message *diam.Message) {
	addMessageCostIdentity(message, "peer.example")
	address := datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))
	message.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address))
	message.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13)))
	message.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("benchmark")))
	message.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
}
