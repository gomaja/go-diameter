package peer

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
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

func TestManagerHandlerDiscoveryScopeTCP(t *testing.T) {
	for _, dialed := range []bool{false, true} {
		for _, allowed := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialed=%t/allowed=%t", dialed, allowed), func(t *testing.T) {
				p := newCoreActivityWire(t, dialed)
				called := make(chan struct{}, 1)
				p.m.HandleIdx(diam.ALL_CMD_INDEX, diam.HandlerFunc(func(c diam.Conn, r *diam.Message) { called <- struct{}{}; _, _ = r.Answer(diam.Success).WriteTo(c) }))
				app := uint32(5)
				if allowed {
					app = 4
				}
				p.a.discovery.Store(&discoveryState{spec: Discovery{Realm: "example.net", ApplicationIDs: []uint32{app}}, expires: p.m.cfg.Now().Add(time.Hour)})
				write(t, p.c, handlerApplicationRequest(t))
				if allowed {
					if answer := read(t, p.c); code(t, answer) != diam.Success {
						t.Fatalf("allowed lease result=%d", code(t, answer))
					}
					<-called
					p.a.discovery.Store(&discoveryState{spec: Discovery{ApplicationIDs: []uint32{4}}, expires: p.m.cfg.Now().Add(-time.Second)})
					if p.s.hasRequestHandler(handlerApplicationRequest(t)) {
						t.Fatal("expired lease retained route")
					}
				} else {
					// Existing unsupported-request reply handling also applies lease scope:
					// the error answer cannot be written outside it, so the session closes.
					e := protocolErrorReceive(t, p.events)
					if e.ReplyCode != diam.CommandUnsupported {
						t.Fatalf("outside lease event=%+v", e)
					}
					select {
					case <-p.s.closed:
					case <-time.After(5 * time.Second):
						t.Fatal("outside-lease reply failure did not close")
					}
					select {
					case <-called:
						t.Fatal("application outside lease reached handler")
					default:
					}
				}
			})
		}
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
