package sm_test

import (
	"errors"
	"fmt"
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

// BenchmarkClientNewConnHandshake measures a complete successful exchange and
// transport cleanup. The peer decodes CER and sends CEA using public APIs.
func BenchmarkClientNewConnHandshake(b *testing.B) {
	for _, transport := range []string{"TCP", "Pipe"} {
		b.Run(transport, func(b *testing.B) {
			dictionary, err := dict.New(dict.Base(), creditcontrol.Dictionary())
			if err != nil {
				b.Fatal(err)
			}
			address := datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))
			machine, err := sm.New(&sm.Settings{
				OriginHost: "client.example", OriginRealm: "example", VendorID: 13,
				ProductName: "benchmark", HostIPAddresses: []datatype.Address{address},
				AuthApplicationID: []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))},
				Dict:              dictionary,
			})
			if err != nil {
				b.Fatal(err)
			}
			client := &sm.Client{
				Handler: machine, Dict: dictionary, RetransmitInterval: time.Second,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			var listener net.Listener
			if transport == "TCP" {
				listener, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = listener.Close() })
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var clientSide, peer net.Conn
				if transport == "TCP" {
					clientSide, err = net.Dial("tcp", listener.Addr().String())
					if err == nil {
						peer, err = listener.Accept()
					}
					if err != nil {
						if clientSide != nil {
							_ = clientSide.Close()
						}
						b.Fatal(err)
					}
				} else {
					clientSide, peer = net.Pipe()
				}
				peerDone := make(chan error, 1)
				go func() { peerDone <- exchangeHandshake(peer, dictionary, address) }()
				conn, err := client.NewConn(clientSide, clientSide.RemoteAddr().String())
				if err != nil {
					_ = clientSide.Close()
					_ = peer.Close()
					b.Fatal(err)
				}
				done, ok := conn.(interface{ DispatchDone() <-chan struct{} })
				if !ok {
					conn.Close()
					_ = peer.Close()
					b.Fatal("native connection does not expose dispatch completion")
				}
				conn.Close()
				<-done.DispatchDone()
				if err := <-peerDone; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}

func exchangeHandshake(peer net.Conn, dictionary *dict.Parser, address datatype.Address) error {
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		return err
	}
	cer, err := diam.ReadMessage(peer, dictionary)
	if err != nil {
		return err
	}
	if cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 || cer.Header.ApplicationID != 0 {
		return fmt.Errorf("unexpected CER header: %+v", cer.Header)
	}
	cea := cer.Answer(diam.Success)
	cea.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	cea.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	cea.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, address))
	cea.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13)))
	cea.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("benchmark")))
	cea.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	if _, err := cea.WriteTo(peer); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := peer.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("after CEA: received %d bytes, error %v", n, err)
	}
	return nil
}
