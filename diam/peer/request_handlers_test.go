package peer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestRequestHandlerDeliverySize(t *testing.T) {
	// The pre-handler protocolDelivery is 80 bytes on 64-bit platforms.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit allocation-class check")
	}
	if got := unsafe.Sizeof(protocolDelivery{}); got != 80 {
		t.Fatalf("protocolDelivery = %d bytes; want 80", got)
	}
	t.Logf("protocolDelivery = %d bytes", unsafe.Sizeof(protocolDelivery{}))
}

func TestManagerHandleIdxRegistration(t *testing.T) {
	handler := diam.HandlerFunc(func(diam.Conn, *diam.Message) {})
	valid := diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}
	cases := []struct {
		name      string
		index     diam.CommandIndex
		handler   diam.Handler
		duplicate bool
	}{
		{"nil interface", valid, nil, false},
		{"nil function", valid, diam.HandlerFunc(nil), false},
		{"duplicate", valid, handler, true},
		{"answer", diam.CommandIndex{AppID: 4, Code: diam.ReAuth}, handler, false},
		{"unadvertised application", diam.CommandIndex{AppID: 0x00fffffe, Code: diam.ReAuth, Request: true}, handler, false},
	}
	for _, app := range []uint32{0, 4} {
		for _, cmd := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			cases = append(cases, struct {
				name      string
				index     diam.CommandIndex
				handler   diam.Handler
				duplicate bool
			}{fmt.Sprintf("core command %d app %d", cmd, app), diam.CommandIndex{AppID: app, Code: cmd, Request: true}, handler, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net")})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			if tc.duplicate {
				m.HandleIdx(tc.index, handler)
			}
			defer func() {
				if recover() == nil {
					t.Fatal("registration did not panic")
				}
			}()
			m.HandleIdx(tc.index, tc.handler)
		})
	}
	t.Run("catch all", func(t *testing.T) {
		m, err := New(Config{Settings: testSettings("local.example.net")})
		if err != nil {
			t.Fatal(err)
		}
		defer closeManager(t, m, nil)
		m.HandleIdx(diam.ALL_CMD_INDEX, handler)
	})
}

func TestManagerRequestHandlerLimitDefault(t *testing.T) {
	for _, limit := range []int{-1, 0, 3} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			m, err := New(Config{Settings: testSettings("local.example.net"), Limits: Limits{HandlersPerConnection: limit}})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			c := newFakeConn()
			s := m.newSession(c, nil, 1, false)
			if s == nil {
				t.Fatal("newSession failed")
			}
			defer s.close()
			want := limit
			if want <= 0 {
				want = 64
			}
			if got := cap(s.handlerSlots); got != want {
				t.Fatalf("handler capacity=%d want %d", got, want)
			}
		})
	}
}

func handlerApplicationRequest(t *testing.T) *diam.Message {
	t.Helper()
	req := diam.NewMessage(diam.ReAuth, diam.RequestFlag|diam.ProxiableFlag, 4, 0x12345678, 0x98765432, newTestDictionary())
	req.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("handlers;1")))
	req.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("known.example.net")))
	req.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	req.AddAVP(diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	req.AddAVP(diam.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity("local.example.net")))
	req.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	req.AddAVP(diam.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Enumerated(0)))
	return req
}

func TestRequestHandlerConnRejectsRequestFrames(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			a, s, _ := newReportingRawActor(t)
			native := &capabilityWireConn{fakeConn: s.c.(*fakeConn), wire: make(chan []byte, 2)}
			s.c = native
			c := &requestHandlerConn{Conn: native, s: s}
			req := handlerApplicationRequest(t)
			wire, err := req.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			var n int
			if stream {
				n, err = c.WriteStream(wire, 5)
			} else {
				n, err = c.Write(wire)
			}
			if n != 0 || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("request write=%d,%v", n, err)
			}
			select {
			case got := <-native.wire:
				t.Fatalf("rejected request reached transport: %x", got)
			default:
			}
			if native.Closed() {
				t.Fatal("request rejection closed connection")
			}
			answer := req.Answer(diam.Success)
			wire, err = answer.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if stream {
				n, err = c.WriteStream(wire, 5)
			} else {
				n, err = c.Write(wire)
			}
			if err != nil || n != len(wire) {
				t.Fatalf("answer write=%d,%v", n, err)
			}
			if got := <-native.wire; !bytes.Equal(got, wire) {
				t.Fatalf("answer wire=%x want %x", got, wire)
			}
			if _, ok := diam.ConnAs[diam.CloseNotifier](c); !ok {
				t.Fatal("ConnAs lost CloseNotifier")
			}
			if c.Unwrap() != native {
				t.Fatal("Unwrap lost native connection")
			}
			_ = a
		})
	}
}

func TestRequestHandlerConnExpiredLease(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			a, s, _ := newReportingRawActor(t)
			native := &capabilityWireConn{fakeConn: s.c.(*fakeConn), wire: make(chan []byte, 1)}
			s.c = native
			a.discovery.Store(&discoveryState{spec: Discovery{ApplicationIDs: []uint32{4}}, expires: a.m.cfg.Now().Add(-time.Second)})
			c := &requestHandlerConn{Conn: native, s: s}
			wire, err := handlerApplicationRequest(t).Answer(diam.Success).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			var n int
			if stream {
				n, err = c.WriteStream(wire, 3)
			} else {
				n, err = c.Write(wire)
			}
			if n != 0 || !errors.Is(err, ErrLeaseExpired) {
				t.Fatalf("expired write=%d,%v", n, err)
			}
			select {
			case got := <-native.wire:
				t.Fatalf("expired write reached wire: %x", got)
			default:
			}
			if native.Closed() {
				t.Fatal("lease refusal closed connection")
			}
		})
	}
}

func TestRequestHandlerConnWriteFailure(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			a, s, _ := newReportingRawActor(t)
			records := logtest.New()
			a.m.cfg.Logger = records.Logger()
			native := &failingWriteConn{fakeConn: s.c.(*fakeConn)}
			s.c = native
			c := &requestHandlerConn{Conn: native, s: s}
			wire, err := handlerApplicationRequest(t).Answer(diam.Success).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if stream {
				_, err = c.WriteStream(wire, 3)
			} else {
				_, err = c.Write(wire)
			}
			if err == nil {
				t.Fatal("write succeeded")
			}
			if !native.Closed() {
				t.Fatal("failed transport remained open")
			}
			got := records.Records()
			if len(got) != 1 || got[0].Level != slog.LevelError || got[0].Message != "peer: write failed; closing connection" {
				t.Fatalf("failure records=%+v", got)
			}
		})
	}
}

func TestManagerHandlerNilDeliveryDispatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, s, _ := newReportingRawActor(t)
		reportingOpen(t, s)
		s.handlerSlots = make(chan struct{}, 1)
		s.handlerConn = &requestHandlerConn{Conn: s.c, s: s}
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		a.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(_ diam.Conn, _ *diam.Message) { close(started); <-release; close(done) }))
		// The real actor owns one Manager work item while admitting this event.
		a.m.wg.Add(1)
		a.handleEvent(event{kind: wireEvent, s: s, msg: handlerApplicationRequest(t)})
		a.m.wg.Done()
		synctest.Wait()
		select {
		case <-started:
		default:
			t.Fatal("delivery without reader never dispatched")
		}
		if !s.protocolInFlight() {
			t.Fatal("running handler not included in in-flight scan")
		}
		close(release)
		<-done
		synctest.Wait()
		if s.protocolInFlight() || s.handlersInFlight.Load() != 0 || len(s.handlerSlots) != 0 {
			t.Fatal("handler accounting or slot leaked")
		}
		waited := make(chan struct{})
		go func() { a.m.wg.Wait(); close(waited) }()
		synctest.Wait()
		select {
		case <-waited:
		default:
			t.Fatal("Manager accounting leaked")
		}
	})
}

func TestManagerHandledRequestWatchdogTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("dialed=%t", dialed), func(t *testing.T) {
			p := newCoreActivityWire(t, dialed)
			p.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(c diam.Conn, req *diam.Message) { _, _ = req.Answer(diam.Success).WriteTo(c) }))
			_ = p.suspect(t)
			write(t, p.c, handlerApplicationRequest(t))
			answer := read(t, p.c)
			if code(t, answer) != diam.Success {
				t.Fatalf("handled request result=%d", code(t, answer))
			}
			p.fence(t)
			if got := p.state(t); got.health != WatchdogOkay {
				t.Fatalf("handled activity retained state %+v", got)
			}
			select {
			case e := <-p.events:
				t.Fatalf("handled request emitted protocol error: %+v", e)
			default:
			}
		})
	}
}

func TestManagerHandlerRequestReopenDiscardTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("dialed=%t", dialed), func(t *testing.T) {
			p := newCoreActivityWire(t, dialed)
			called := make(chan struct{}, 1)
			p.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { called <- struct{}{} }))
			_ = p.c.Close()
			awaitState(t, p.m, Closed)
			p.fence(t)
			if dialed {
				p.a.post(event{kind: start})
			}
			p.connect(t)
			probe := read(t, p.c)
			if probe.Header.CommandCode != diam.DeviceWatchdog {
				t.Fatalf("reopen probe=%+v", probe.Header)
			}
			write(t, p.c, handlerApplicationRequest(t))
			// DWR/DWA is an ordered wire fence after the discarded application request.
			write(t, p.c, watchdogRequest(t))
			if ans := read(t, p.c); ans.Header.CommandCode != diam.DeviceWatchdog {
				t.Fatalf("unexpected application answer in REOPEN: %+v", ans.Header)
			}
			p.fence(t)
			if got := p.state(t); got.health != WatchdogReopen {
				t.Fatalf("request escaped REOPEN: %+v", got)
			}
			select {
			case <-called:
				t.Fatal("REOPEN request reached handler")
			default:
			}
		})
	}
}

// RFC 6733 §7.1.3: an unrouted request keeps its protocol error answer.
func TestManagerHandlerDiscoveryScopeTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, registered := range []bool{false, true} {
			for _, proxiable := range []bool{false, true} {
				for _, tc := range []struct {
					name    string
					app     uint32
					expired bool
					want    uint32
				}{
					{"inside", 4, false, diam.CommandUnsupported},
					{"outside-advertised", 5, false, diam.CommandUnsupported},
					{"outside-unadvertised", 0x00fffffe, false, diam.ApplicationUnsupported},
					{"expired", 4, true, 0},
				} {
					if !proxiable && (tc.name == "inside" || tc.expired) {
						continue
					}
					t.Run(fmt.Sprintf("dialed=%t/handler=%t/P=%t/%s", dialed, registered, proxiable, tc.name), func(t *testing.T) {
						records := logtest.New()
						p := newCoreActivityWireConfigured(t, dialed, func(cfg *Config) {
							cfg.Logger = records.Logger()
							// A synthetic command without a P constraint covers non-proxiable requests
							// without violating RAR's required P bit.
							if err := cfg.Settings.Dict.Load(strings.NewReader(`<diameter><application id="5" name="LeaseProbe"><command code="65244" name="LeaseProbe" short="LP"><request><rule avp="AVP"/></request><answer><rule avp="AVP"/></answer></command></application></diameter>`)); err != nil {
								t.Fatal(err)
							}
							cfg.Settings.AuthApplicationID = []*diam.AVP{
								diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
								diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(5)),
							}
						})
						called := make(chan uint32, 2)
						writes := make(chan error, 2)
						if registered {
							p.m.HandleIdx(diam.ALL_CMD_INDEX, diam.HandlerFunc(func(c diam.Conn, r *diam.Message) {
								called <- r.Header.HopByHopID
								_, err := r.Answer(diam.Success).WriteTo(c)
								writes <- err
							}))
						}
						expires := p.m.cfg.Now().Add(time.Hour)
						if tc.expired {
							expires = p.m.cfg.Now().Add(-time.Second)
						}
						p.a.discovery.Store(&discoveryState{spec: Discovery{Realm: "example.net", ApplicationIDs: []uint32{4}}, expires: expires})
						req := handlerApplicationRequest(t)
						req.Header.ApplicationID = tc.app
						req.Header.CommandFlags = diam.RequestFlag | diam.RetransmittedFlag
						if proxiable {
							req.Header.CommandFlags |= diam.ProxiableFlag
						} else {
							// Use the synthetic command for the non-P case.
							req.Header.CommandCode = 0xfedc
						}
						before := p.state(t)
						write(t, p.c, req)
						if tc.expired {
							if err := p.c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
								t.Fatal(err)
							}
							var b [1]byte
							if n, err := p.c.Read(b[:]); n != 0 || err != io.EOF {
								t.Fatalf("expired lease read=%d,%v; want EOF without answer", n, err)
							}
							select {
							case <-p.s.closed:
							case <-time.After(5 * time.Second):
								t.Fatal("expired session remained open")
							}
						} else {
							want := tc.want
							if tc.app == 4 && registered {
								want = diam.Success
							}
							checkDiscoveryScopeAnswer(t, p, req, want)
							after := p.state(t)
							if after.token == before.token || after.health != before.health || after.pending != before.pending {
								t.Fatalf("request activity credit changed: before=%+v after=%+v", before, after)
							}
							if want == diam.Success {
								checkDiscoveryScopeHandler(t, called, writes, req.Header.HopByHopID)
							}
							// An ordered DWR/DWA fence proves that dispatch and the connection
							// remain usable after the required application answer.
							dwr := watchdogRequest(t)
							write(t, p.c, dwr)
							if dwa := read(t, p.c); dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.CommandFlags != 0 || dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID || code(t, dwa) != diam.Success {
								t.Fatalf("DWR round trip failed: %+v", dwa)
							}
							inScope := handlerApplicationRequest(t)
							inScope.Header.HopByHopID++
							write(t, p.c, inScope)
							want = diam.CommandUnsupported
							if registered {
								want = diam.Success
							}
							checkDiscoveryScopeAnswer(t, p, inScope, want)
							if registered {
								checkDiscoveryScopeHandler(t, called, writes, inScope.Header.HopByHopID)
							}
						}
						p.fence(t)
						select {
						case id := <-called:
							t.Fatalf("request outside lease reached handler: %x", id)
						default:
						}
						select {
						case e := <-p.events:
							if !tc.expired {
								t.Fatalf("unexpected protocol event: %+v", e)
							}
						default:
						}
						for _, r := range records.Records() {
							if !tc.expired && r.Level >= slog.LevelError {
								t.Errorf("unexpected Error record: %s", r.Message)
							}
						}
					})
				}
			}
		}
	}
}

func checkDiscoveryScopeHandler(t *testing.T, called <-chan uint32, writes <-chan error, want uint32) {
	t.Helper()
	select {
	case id := <-called:
		if id != want {
			t.Fatalf("handler request=%x; want %x", id, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-scope handler not called")
	}
	select {
	case err := <-writes:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler write did not finish")
	}
}

func checkDiscoveryScopeAnswer(t *testing.T, p *coreActivityWire, req *diam.Message, want uint32) {
	t.Helper()
	if err := p.c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var header [20]byte
	if _, err := io.ReadFull(p.c, header[:]); err != nil {
		t.Fatal(err)
	}
	flags := req.Header.CommandFlags & diam.ProxiableFlag
	if want != diam.Success {
		flags |= diam.ErrorFlag
	}
	if header[0] != 1 || header[4] != flags || uint32(header[5])<<16|uint32(header[6])<<8|uint32(header[7]) != req.Header.CommandCode || binary.BigEndian.Uint32(header[8:12]) != req.Header.ApplicationID || binary.BigEndian.Uint32(header[12:16]) != req.Header.HopByHopID || binary.BigEndian.Uint32(header[16:20]) != req.Header.EndToEndID {
		t.Fatalf("answer wire header=%x; request=%+v", header, req.Header)
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length < len(header) || length > 4096 {
		t.Fatalf("answer length=%d", length)
	}
	wire := make([]byte, length)
	copy(wire, header[:])
	if _, err := io.ReadFull(p.c, wire[len(header):]); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(bytes.NewReader(wire), p.m.dictionary())
	if err != nil {
		t.Fatal(err)
	}
	if got := code(t, answer); got != want {
		t.Fatalf("answer result=%d; want %d; wire=%x", got, want, wire)
	}
	if want == diam.Success {
		return
	}
	// RFC 6733 §6.2 and Verified Erratum 4887 require local origins.
	for avpCode, wantOrigin := range map[uint32]string{avp.OriginHost: "local.example.net", avp.OriginRealm: "example.net"} {
		origin, err := answer.FindAVP(avpCode, 0)
		if err != nil || origin.Data != datatype.DiameterIdentity(wantOrigin) {
			t.Fatalf("origin %d=%v,%v; wire=%x", avpCode, origin, err, wire)
		}
	}
	kind := diam.ProtocolUnsupportedCommand
	if want == diam.ApplicationUnsupported {
		kind = diam.ProtocolUnsupportedApplication
	}
	protocolErrorCheck(t, protocolErrorReceive(t, p.events), p.s.c, *req.Header, kind, want, false, diam.ProtocolReplyQueued, want, 0)
}

func TestManagerSendOutsideDiscoveryScopeTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		t.Run(fmt.Sprintf("dialed=%t", dialed), func(t *testing.T) {
			p := newCoreActivityWire(t, dialed)
			p.a.discovery.Store(&discoveryState{spec: Discovery{Realm: "example.net", ApplicationIDs: []uint32{5}}, expires: p.m.cfg.Now().Add(time.Hour)})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if answer, err := p.m.Send(ctx, outboundRequest("known.example.net", "example.net")); answer != nil || !errors.Is(err, ErrUnableToDeliver) {
				t.Fatalf("outside lease Send=%v,%v", answer, err)
			}
			// A DWA must be the next frame: no refused application request may leak.
			dwr := watchdogRequest(t)
			write(t, p.c, dwr)
			if answer := read(t, p.c); answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.CommandFlags != 0 || code(t, answer) != diam.Success {
				t.Fatalf("refused Send reached wire or closed connection: %+v", answer)
			}
		})
	}
}

func TestManagerHandlerRetirementReleasesBlockedSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 0, true, false, func(cfg *Config) { cfg.Limits.HandlersPerConnection = 1 })
		h.open(t)
		old := h.m.getSession(h.initial)
		running, release := make(chan struct{}), make(chan struct{})
		h.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(running); <-release }))
		h.feed(t, handlerApplicationRequest(t))
		<-running
		synctest.Wait()
		// This is the delivery consumer's reservation after Admit. Retirement is
		// independent of the reader and must release that consumer's slot wait.
		old.handlersInFlight.Add(1)
		h.m.wg.Add(1)
		waiting := make(chan struct{})
		go func() { old.dispatchRequest(handlerApplicationRequest(t)); close(waiting) }()
		synctest.Wait()
		select {
		case <-waiting:
			t.Fatal("saturated slot did not block")
		default:
		}
		if err := h.m.HandleRetire(h.initial, diam.AcceptedCERRenewal); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-waiting:
		default:
			t.Fatal("retirement did not wake blocked delivery")
		}
		if got := old.handlersInFlight.Load(); got != 1 {
			t.Fatalf("after drop in-flight=%d want 1 running", got)
		}
		close(release)
		synctest.Wait()
		if got := old.handlersInFlight.Load(); got != 0 {
			t.Fatalf("retired in-flight=%d", got)
		}
		var warnings int
		for _, r := range h.records.Records() {
			if r.Level == slog.LevelWarn {
				warnings++
			}
		}
		if warnings != 1 {
			t.Fatalf("dropped request warnings=%d want 1", warnings)
		}
	})
}

func TestManagerHandlerRetiredGenerationWriteTCP(t *testing.T) {
	pairs := make(chan renewalScriptPair, 1)
	p := newCoreActivityWire(t, false, func(server *diam.Server) {
		server.RenewAcceptedCER = true
		server.OnConnectionRestart = func(old, next diam.Conn, reason diam.RetirementReason) { pairs <- renewalScriptPair{old, next, reason} }
	})
	old := p.s
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	type result struct {
		err  error
		meta *smpeer.Metadata
	}
	entered, finished := make(chan *smpeer.Metadata, 2), make(chan result, 2)
	p.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(c diam.Conn, r *diam.Message) {
		meta, _ := smpeer.FromContext(c.Context())
		entered <- meta
		if r.Header.HopByHopID == 0x12345678 {
			<-release
		}
		_, err := r.Answer(diam.Success).WriteTo(c)
		if r.Header.HopByHopID == 0x12345678 {
			// A late Close belongs to this retired session; it must not
			// close the renewed owner of the same physical transport.
			c.Close()
		}
		finished <- result{err, meta}
	}))
	write(t, p.c, handlerApplicationRequest(t))
	first := renewalScriptReceive(t, entered, "old handler")
	if first == nil || first.OriginRealm != "example.net" {
		t.Fatalf("old metadata=%+v", first)
	}
	replacement := renewalScriptCER(t, "known.example.net", "fresh.example.net", 4, 222)
	write(t, p.c, replacement)
	pair := renewalScriptReceive(t, pairs, "TCP replacement")
	if answer := read(t, p.c); answer.Header.CommandCode != diam.CapabilitiesExchange || code(t, answer) != diam.Success {
		t.Fatalf("replacement CEA=%+v", answer)
	}
	p.s = p.m.getSession(pair.next)
	if p.s == nil || p.s == old || pair.old != old.c {
		t.Fatal("renewal did not install distinct generation")
	}
	probe := read(t, p.c)
	for want := 1; want <= 3; want++ {
		dwa, err := base.BuildDWA(probe, testBase("known.example.net"))
		if err != nil {
			t.Fatal(err)
		}
		// The replacement advertised a new Origin-Realm; use its identity for
		// watchdog recovery on this physical association.
		for _, field := range dwa.AVP {
			if field.Code == avp.OriginRealm && field.VendorID == 0 {
				field.Data = datatype.DiameterIdentity("fresh.example.net")
			}
		}
		write(t, p.c, dwa)
		dwr := watchdogRequest(t)
		for _, field := range dwr.AVP {
			if field.Code == avp.OriginRealm && field.VendorID == 0 {
				field.Data = datatype.DiameterIdentity("fresh.example.net")
			}
		}
		write(t, p.c, dwr)
		if answer := read(t, p.c); answer.Header.CommandCode != diam.DeviceWatchdog {
			t.Fatalf("old handler leaked frame: %+v", answer.Header)
		}
		p.fence(t)
		if want != 3 {
			p.expire(t)
			probe = read(t, p.c)
		}
	}
	// Release after the new generation is fully usable: its native write fence
	// must still reject the old handler's answer.
	unblock()
	got := renewalScriptReceive(t, finished, "retired handler write")
	if !errors.Is(got.err, diam.ErrConnectionRetired) {
		t.Fatalf("old answer write=%v", got.err)
	}
	if got.meta != first || first.OriginRealm != "example.net" {
		t.Fatal("renewal mutated old metadata")
	}
	if pair.next.Closed() {
		t.Fatal("retired handler Close closed replacement")
	}
	dwr := watchdogRequest(t)
	for _, field := range dwr.AVP {
		if field.Code == avp.OriginRealm && field.VendorID == 0 {
			field.Data = datatype.DiameterIdentity("fresh.example.net")
		}
	}
	write(t, p.c, dwr)
	dwa := read(t, p.c)
	if dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.CommandFlags != 0 || dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID || code(t, dwa) != diam.Success {
		t.Fatalf("watchdog after retired handler Close=%+v", dwa)
	}
	request := handlerApplicationRequest(t)
	request.Header.HopByHopID++
	for _, field := range request.AVP {
		if field.Code == avp.OriginRealm && field.VendorID == 0 {
			field.Data = datatype.DiameterIdentity("fresh.example.net")
		}
	}
	write(t, p.c, request)
	answer := read(t, p.c)
	if answer.Header.HopByHopID != request.Header.HopByHopID || code(t, answer) != diam.Success {
		t.Fatalf("new handler answer=%+v", answer)
	}
	next := renewalScriptReceive(t, entered, "new handler")
	if next == nil || next == first || next.OriginRealm != "fresh.example.net" {
		t.Fatalf("new metadata=%+v", next)
	}
	if got := renewalScriptReceive(t, finished, "new handler write"); got.err != nil {
		t.Fatal(got.err)
	}
	if pair.next.Closed() {
		t.Fatal("old write closed replacement session")
	}
}

func TestManagerHandlerElectionSelectedLeg(t *testing.T) {
	for _, initiator := range []bool{false, true} {
		t.Run(fmt.Sprintf("initiator=%t", initiator), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local := "z.example.net"
				if initiator {
					local = "a.example.net"
				}
				m, a, i, r, _ := renewalCompositionActor(t, WaitReturns, local, true, false, false)
				t.Cleanup(func() {
					// These composition legs have no native read workers to
					// publish transport loss when the selected fixture closes.
					i.close()
					r.close()
					a.post(event{kind: connGone, s: i})
					a.post(event{kind: connGone, s: r})
				})
				wireI := &capabilityWireConn{fakeConn: i.c.(*fakeConn), wire: make(chan []byte, 4)}
				wireR := &capabilityWireConn{fakeConn: r.c.(*fakeConn), wire: make(chan []byte, 4)}
				renewalCompositionCommit(a, event{testHook: func() {
					i.c, r.c = wireI, wireR
					for _, s := range []*session{i, r} {
						s.handlerSlots = make(chan struct{}, 1)
						s.handlerConn = &requestHandlerConn{Conn: s.c, s: s}
					}
				}})
				called := make(chan diam.Conn, 1)
				m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
					answer := request.Answer(diam.Success)
					answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(local)))
					answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
					_, _ = answer.WriteTo(c)
					called <- c
				}))
				renewalCompositionCommit(a, event{testHook: a.elect})
				target, other := r, i
				targetWire, otherWire := wireR, wireI
				if initiator {
					renewalCompositionCEA(t, m, a, i)
					target, other = i, r
					targetWire, otherWire = wireI, wireR
				} else {
					// Complete the election's selected responder CEA through the existing
					// fixture writer before admitting application requests on that leg.
					renewalCompositionCommit(a, event{testHook: func() { fixtureCompleteWrite(r, requiredQueuedWrite(t, r)) }})
					ceaWire := renewalScriptReceive(t, wireR.wire, "elected responder CEA")
					cea, err := diam.ReadMessage(bytes.NewReader(ceaWire), m.dictionary())
					if err != nil || cea.Header.CommandCode != diam.CapabilitiesExchange || code(t, cea) != diam.Success {
						t.Fatalf("elected CEA=%v err=%v", cea, err)
					}
				}
				synctest.Wait()
				if a.activeSession.Load() != target || !other.c.Closed() {
					t.Fatal("election did not select exactly one leg")
				}
				request := handlerApplicationRequest(t)
				a.post(event{kind: wireEvent, s: target, msg: request})
				synctest.Wait()
				select {
				case c := <-called:
					if c.(*requestHandlerConn).Unwrap() != target.c {
						t.Fatal("handler was given opposite leg")
					}
				default:
					t.Fatal("elected leg did not dispatch")
				}
				select {
				case wire := <-targetWire.wire:
					answer, err := diam.ReadMessage(bytes.NewReader(wire), m.dictionary())
					if err != nil {
						t.Fatal(err)
					}
					if code(t, answer) != diam.Success || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || answer.Header.CommandFlags != diam.ProxiableFlag {
						t.Fatalf("elected answer=%+v", answer)
					}
				default:
					t.Fatal("handler did not answer on selected leg")
				}
				select {
				case wire := <-otherWire.wire:
					t.Fatalf("answer reached opposite leg: %x", wire)
				default:
				}
				if target.handlersInFlight.Load() != 0 {
					t.Fatal("elected handler accounting leaked")
				}
			})
		})
	}
}

func TestManagerHandlerWatchdogWakesBlockedSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := renewalScriptNew(t, 0, false, false, func(cfg *Config) {
			cfg.Limits.HandlersPerConnection = 1
			cfg.Timers.TwInit = time.Second
			cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
		})
		h.open(t)
		s := h.m.getSession(h.initial)
		a, _ := s.binding()
		entered, release := make(chan struct{}), make(chan struct{})
		defer close(release)
		h.m.HandleIdx(diam.CommandIndex{AppID: 4, Code: diam.ReAuth, Request: true}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(entered); <-release }))
		h.feed(t, handlerApplicationRequest(t))
		<-entered
		synctest.Wait()
		h.feed(t, handlerApplicationRequest(t))
		synctest.Wait()
		if got := s.handlersInFlight.Load(); got != 2 {
			t.Fatalf("in-flight=%d want running+slot waiter", got)
		}
		expire := func() {
			t.Helper()
			var timer *fakeTimer
			renewalCompositionCommit(a, event{testHook: func() { timer, _ = fixtureWatchdogTimer(a).(*fakeTimer) }})
			if timer == nil {
				t.Fatal("watchdog did not arm the fake clock")
			}
			timer.mu.Lock()
			active := timer.active
			timer.active = false
			timer.mu.Unlock()
			if !active {
				t.Fatal("watchdog timer already stopped")
			}
			timer.f()
			synctest.Wait()
		}
		expire()
		if probe := h.message(t); probe.Header.CommandCode != diam.DeviceWatchdog {
			t.Fatalf("watchdog probe=%+v", probe.Header)
		}
		expire()
		if got := a.snapshot().Watchdog; got != WatchdogSuspect {
			t.Fatalf("watchdog=%v want Suspect", got)
		}
		expire()
		synctest.Wait()
		select {
		case <-s.closed:
		default:
			t.Fatal("watchdog did not close saturated session")
		}
		if got := s.handlersInFlight.Load(); got != 1 {
			t.Fatalf("slot waiter retained accounting after watchdog: %d", got)
		}
		var dropped int
		for _, record := range h.records.Records() {
			if record.Message == "peer: request handler dropped; connection closed" {
				if record.Level != slog.LevelWarn {
					t.Fatalf("drop level=%v", record.Level)
				}
				dropped++
			}
		}
		if dropped != 1 {
			t.Fatalf("dropped request logs=%d want 1", dropped)
		}
	})
}
