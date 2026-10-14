//go:build linux && !386 && sctprestart

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
	"github.com/gomaja/go-sctp"
)

type contextKey struct{}
type tracked struct{ *sm.StateMachine }

func (t *tracked) Unwrap() diam.Handler { return t.StateMachine }
func (t *tracked) HandleAccept(c diam.Conn) func() {
	log.Printf("ACCEPT_HOOK conn=%p generation=%d", c, generation(c))
	cleanup := t.StateMachine.HandleAccept(c)
	return func() {
		if cleanup != nil {
			cleanup()
		}
		log.Printf("ACCEPT_CLEANUP conn=%p generation=%d", c, generation(c))
	}
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func app(id uint32) *diam.AVP {
	return diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(id))
}
func generation(c diam.Conn) uint64 {
	if x, ok := c.(interface{ Generation() uint64 }); ok {
		return x.Generation()
	}
	return 0
}

// observedListener records the ordered adapter boundary on the Docker kernel.
// RFC 6458 §6.1.1 identifies association-change notifications; RFC 9260 §5.2.4
// describes restart. There is exactly one physical receive consumer.
type observedListener struct{ net.Listener }

func (l observedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	log.Printf("SOCKET_ACCEPT conn=%p local=%s remote=%s", c, c.LocalAddr(), c.RemoteAddr())
	msc, ok := c.(diam.MultistreamConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("accepted transport %T is not multistream", c)
	}
	return &observedConn{MultistreamConn: msc}, nil
}

type observedConn struct {
	diam.MultistreamConn
	index atomic.Uint64
}

func restartMarker(err error) bool {
	for err != nil {
		typ := reflect.TypeOf(err)
		if typ.Kind() == reflect.Pointer && typ.Elem().Name() == "TransportRestartError" {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
func (c *observedConn) record(b []byte, n int, stream uint, err error) {
	if n == 0 && err == nil {
		return
	}
	head := n
	if head > 20 {
		head = 20
	}
	log.Printf("TRANSPORT_READ index=%d bytes=%d stream=%d restart=%t error=%v head=%x", c.index.Add(1), n, stream, restartMarker(err), err, b[:head])
}
func (c *observedConn) ReadAtLeast(b []byte, min int, stream uint) (int, uint, error) {
	n, actual, err := c.MultistreamConn.ReadAtLeast(b, min, stream)
	c.record(b, n, actual, err)
	return n, actual, err
}
func (c *observedConn) ReadAny(b []byte) (int, uint, error) {
	n, stream, err := c.MultistreamConn.ReadAny(b)
	c.record(b, n, stream, err)
	return n, stream, err
}
func (c *observedConn) ReadStream(b []byte, stream uint) (int, error) {
	n, err := c.MultistreamConn.ReadStream(b, stream)
	c.record(b, n, stream, err)
	return n, err
}
func (c *observedConn) Read(b []byte) (int, error) {
	n, err := c.MultistreamConn.Read(b)
	c.record(b, n, c.CurrentStream(), err)
	return n, err
}
func (c *observedConn) ResetForRestart() {
	if r, ok := c.MultistreamConn.(interface{ ResetForRestart() }); ok {
		r.ResetForRestart()
	} else {
		log.Fatal("transport lacks restart reset")
	}
}

func main() {
	parser, err := dict.New(s6a.Dictionary())
	must(err)
	log.SetFlags(log.Lmicroseconds)
	mode := flag.String("mode", "server", "")
	addr := flag.String("addr", ":3868", "")
	local := flag.String("local", ":43868", "")
	phase := flag.Int("phase", 1, "")
	stream := flag.Uint("stream", 0, "")
	appid := flag.Uint("app", 4, "")
	fragment := flag.Bool("fragment", false, "")
	watchdog := flag.Bool("watchdog", false, "")
	flag.Parse()
	if *mode == "server" {
		settings := &sm.Settings{Dict: parser, OriginHost: "server.example", OriginRealm: "example", VendorID: 0, ProductName: "i81-wire", AuthApplicationID: []*diam.AVP{app(4), app(16777251)}, AcctApplicationID: []*diam.AVP{}, VendorSpecificApplicationID: []*diam.AVP{}, EnableWatchdog: *watchdog, WatchdogInterval: 6 * time.Second,
			OnCER: func(c diam.Conn, m *diam.Message) {
				log.Printf("CER conn=%p generation=%d hop=%x end=%x", c, generation(c), m.Header.HopByHopID, m.Header.EndToEndID)
			},
			OnCEA: func(c diam.Conn, m *diam.Message) {
				log.Printf("CEA conn=%p generation=%d hop=%x end=%x", c, generation(c), m.Header.HopByHopID, m.Header.EndToEndID)
			},
			OnHandshake: func(c diam.Conn, p *smpeer.Metadata) {
				log.Printf("HANDSHAKE conn=%p generation=%d peer=%+v", c, generation(c), p)
			}}
		mux, err := sm.New(settings)
		must(err)
		srv := &diam.Server{Network: "sctp4", Addr: *addr, Handler: &tracked{mux}, Dict: parser, OnNewConnection: func(c diam.Conn) {
			log.Printf("PHYSICAL_ACCEPT conn=%p generation=%d", c, generation(c))
			c.SetContext(context.WithValue(c.Context(), contextKey{}, "old-value"))
			go func() {
				<-c.(diam.CloseNotifier).CloseNotify()
				log.Printf("OLD_CLOSE_NOTIFY conn=%p closed=%t generation=%d", c, c.Closed(), generation(c))
			}()
		}}
		field := reflect.ValueOf(srv).Elem().FieldByName("OnConnectionRestart")
		if field.IsValid() {
			field.Set(reflect.MakeFunc(field.Type(), func(args []reflect.Value) []reflect.Value {
				old := args[0].Interface().(diam.Conn)
				next := args[1].Interface().(diam.Conn)
				log.Printf("RESTART_HOOK old=%p new=%p old_generation=%d new_generation=%d old_closed=%t reason=%v", old, next, generation(old), generation(next), old.Closed(), args[2].Interface())
				if old == next || !old.Closed() || old.Context().Value(contextKey{}) != "old-value" || next.Context().Value(contextKey{}) != nil {
					log.Fatal("generation isolation failed")
				}
				n, err := old.Write([]byte{0})
				log.Printf("OLD_WRITE_FENCE bytes=%d error=%v closed_match=%t", n, err, errors.Is(err, net.ErrClosed))
				if n != 0 || !errors.Is(err, net.ErrClosed) {
					log.Fatal("old write fence failed")
				}
				go func() {
					time.Sleep(100 * time.Millisecond)
					old.Close()
					log.Printf("OLD_CLOSE_FENCE old=%p new_closed=%t", old, next.Closed())
				}()
				return nil
			}))
		}
		log.Printf("LISTENING addr=%s", *addr)
		listener, err := diam.MultistreamListen("sctp4", *addr)
		must(err)
		defer func() { must(listener.Close()) }()
		must(srv.Serve(observedListener{listener}))
		return
	}
	la, err := sctp.ResolveAddr("sctp4", *local)
	must(err)
	ra, err := sctp.ResolveAddr("sctp4", *addr)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cfg := &sctp.Config{InitMsg: sctp.InitMsg{OutStreams: 16, MaxInStreams: 16}, NoDelay: new(true), DefaultSndInfo: &sctp.SndInfo{PPID: 46}}
	start := time.Now()
	c, err := cfg.Dial(ctx, "sctp4", la, ra)
	must(err)
	raw, err := c.SyscallConn()
	must(err)
	var sockerr error
	must(raw.Control(func(fd uintptr) {
		sockerr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
	}))
	must(sockerr)
	log.Printf("SO_LINGER enabled=1 seconds=0 phase=%d", *phase)
	m := diam.NewRequest(diam.CapabilitiesExchange, 0, parser)
	m.Header.HopByHopID = 0x81000000 + uint32(*phase)
	m.Header.EndToEndID = 0x82000000 + uint32(*phase)
	for _, a := range []*diam.AVP{diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("client"+strconv.Itoa(*phase)+".example")), diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")), diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(la.IPs[0])), diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(0)), diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("i81-wire")), diam.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(*phase)), app(uint32(*appid))} {
		m.AddAVP(a)
	}
	b, err := m.Serialize()
	must(err)
	_, err = c.SendMsg(b, sctp.SendOptions{Info: &sctp.SndInfo{Stream: uint16(*stream), PPID: 46}})
	must(err)
	must(c.SetReadDeadline(start.Add(4 * time.Second)))
	answer, err := diam.ReadMessage(c, parser)
	if err != nil {
		log.Fatalf("FAIL phase=%d CEA wait=%s error=%v", *phase, time.Since(start), err)
	}
	var cea struct {
		ResultCode datatype.Unsigned32       `avp:"Result-Code"`
		OriginHost datatype.DiameterIdentity `avp:"Origin-Host"`
	}
	must(answer.Unmarshal(&cea))
	if answer.Header.CommandCode != 257 || answer.Header.CommandFlags&diam.RequestFlag != 0 || cea.ResultCode != 2001 || answer.Header.HopByHopID != m.Header.HopByHopID || answer.Header.EndToEndID != m.Header.EndToEndID {
		log.Fatalf("FAIL mismatched CEA %+v result=%d", answer.Header, cea.ResultCode)
	}
	log.Printf("PASS phase=%d CEA elapsed=%s result=%d hop=%x end=%x stream=%d", *phase, time.Since(start), cea.ResultCode, answer.Header.HopByHopID, answer.Header.EndToEndID, *stream)
	if *phase == 1 {
		if *fragment {
			_, err = c.SendMsg(b[:10], sctp.SendOptions{Info: &sctp.SndInfo{Stream: 3, PPID: 46}})
			must(err)
			log.Printf("OLD_FRAGMENT stream=3 bytes=10")
		}
		must(os.WriteFile("/tmp/initial-ready", []byte("ready"), 0600))
		for {
			time.Sleep(time.Hour)
		}
	}
	// Keep the renewed peer alive until the old Close hook has fired, then prove
	// the renewed generation still handles traffic (RFC 6733 §5.5.1).
	time.Sleep(200 * time.Millisecond)
	dwr := diam.NewRequest(diam.DeviceWatchdog, 0, parser)
	dwr.Header.HopByHopID = 0x81000102
	dwr.Header.EndToEndID = 0x82000102
	dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("client2.example")))
	dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	dwrBytes, err := dwr.Serialize()
	must(err)
	_, err = c.SendMsg(dwrBytes, sctp.SendOptions{Info: &sctp.SndInfo{Stream: uint16(*stream), PPID: 46}})
	must(err)
	dwa, err := diam.ReadMessage(c, parser)
	must(err)
	var result struct {
		ResultCode datatype.Unsigned32 `avp:"Result-Code"`
	}
	must(dwa.Unmarshal(&result))
	if dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.CommandFlags&diam.RequestFlag != 0 || dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID || result.ResultCode != 2001 {
		log.Fatal("post-restart DWA mismatch")
	}
	log.Printf("POST_RESTART_DWA PASS hop=%x end=%x", dwa.Header.HopByHopID, dwa.Header.EndToEndID)
	must(c.Close())
}
