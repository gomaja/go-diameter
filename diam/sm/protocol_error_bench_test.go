package sm_test

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm"
)

// BenchmarkProtocolErrorNilRoundTrip exercises the public server and state
// machine with their default notification configuration. The fixture uses
// only APIs available before protocol-error notifications were introduced.
func BenchmarkProtocolErrorNilRoundTrip(b *testing.B) {
	for _, transport := range []string{"TCP", "Pipe"} {
		b.Run(transport, func(b *testing.B) { benchmarkProtocolErrorNilRoundTrip(b, transport) })
	}
}

func benchmarkProtocolErrorNilRoundTrip(b *testing.B, transport string) {
	dictionary := newTestDictionary(dict.Base(), creditcontrol.Dictionary())
	address := datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))
	machine, err := sm.New(&sm.Settings{
		OriginHost: "server.example", OriginRealm: "example", VendorID: 13,
		ProductName: "benchmark", HostIPAddresses: []datatype.Address{address}, Dict: dictionary,
	})
	if err != nil {
		b.Fatal(err)
	}
	var listener net.Listener
	var client net.Conn
	if transport == "TCP" {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			client, err = net.Dial("tcp", listener.Addr().String())
		}
	} else {
		var accepted net.Conn
		client, accepted = net.Pipe()
		pending := make(chan net.Conn, 1)
		pending <- accepted
		listener = &protocolBenchmarkListener{pending: pending, closed: make(chan struct{})}
	}
	if err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		b.Fatal(err)
	}
	server := &diam.Server{Handler: machine, Dict: dictionary, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	b.Cleanup(func() {
		_ = client.Close()
		if err := server.Close(); err != nil && !errors.Is(err, diam.ErrServerClosed) {
			b.Error(err)
		}
		if err := <-serveDone; err != nil && !errors.Is(err, diam.ErrServerClosed) {
			b.Error(err)
		}
	})
	if err := client.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dictionary)
	cer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	cer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	cer.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address))
	cer.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13)))
	cer.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	cer.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("benchmark")))
	if _, err := cer.WriteTo(client); err != nil {
		b.Fatal(err)
	}
	checkProtocolBenchmarkAnswer(b, client, cer.Header, dictionary)
	dwr := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 3, 4, dictionary)
	dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	wire, err := dwr.Serialize()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := client.Write(wire); err != nil || n != len(wire) {
			b.Fatalf("write = %d, %v; want %d bytes", n, err, len(wire))
		}
		checkProtocolBenchmarkAnswer(b, client, dwr.Header, dictionary)
	}
	b.StopTimer()
}

func checkProtocolBenchmarkAnswer(b *testing.B, client net.Conn, request *diam.Header, dictionary *dict.Parser) {
	b.Helper()
	answer, err := diam.ReadMessage(client, dictionary)
	if err != nil {
		b.Fatal(err)
	}
	if answer.Header.CommandCode != request.CommandCode || answer.Header.CommandFlags != 0 ||
		answer.Header.ApplicationID != request.ApplicationID || answer.Header.HopByHopID != request.HopByHopID ||
		answer.Header.EndToEndID != request.EndToEndID {
		b.Fatalf("unexpected answer header: %+v", answer.Header)
	}
	result, err := answer.FindAVP(avp.ResultCode, 0)
	if err != nil || result.Data != datatype.Unsigned32(diam.Success) {
		b.Fatalf("answer Result-Code = %v, %v; want success", result, err)
	}
}

type protocolBenchmarkListener struct {
	pending chan net.Conn
	closed  chan struct{}
	once    sync.Once
}

func (l *protocolBenchmarkListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.pending:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *protocolBenchmarkListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *protocolBenchmarkListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
