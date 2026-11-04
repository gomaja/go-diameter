package peer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func requestHandlerAnswer(request *diam.Message) *diam.Message {
	answer := request.Answer(diam.Success)
	if session, err := request.FindAVP(avp.SessionID, 0); err == nil {
		answer.AddAVP(session)
	}
	answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("local.example.net")))
	answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	return answer
}

func requestHandlerFrontends(t *testing.T, test func(*testing.T, parityFrontend, int)) {
	t.Helper()
	for _, frontend := range parityFrontends {
		if !frontend.manager {
			continue
		}
		for _, concurrency := range []int{0, 8} {
			t.Run(fmt.Sprintf("%s/concurrency=%d", frontend.name, concurrency), func(t *testing.T) {
				test(t, frontend, concurrency)
			})
		}
	}
}

func requestHandlerSilence(t *testing.T, h *parityTCP) {
	t.Helper()
	if err := h.wire.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := h.wire.Read(b[:])
	var timeout net.Error
	if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("wire was not silent: bytes=%d error=%v", n, err)
	}
}

func requestHandlerAwaitAdmission(t *testing.T, h *parityTCP, want int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		got := peer.RequestHandlersInFlightForTesting(h.manager)
		if got == want {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("admitted handler requests=%d; want %d: %v", got, want, ctx.Err())
		}
	}
}

func TestManagerRequestHandlersTCPRouting(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		for _, scenario := range []string{"route", "catch-all", "no-route", "unadvertised", "invalid", "decode"} {
			t.Run(scenario, func(t *testing.T) {
				calls := make(chan *diam.Message, 4)
				writes := make(chan error, 4)
				options := paritySettings{serverConcurrency: concurrency, catchAll: scenario == "catch-all" || scenario == "unadvertised"}
				if scenario != "no-route" {
					options.requestHandler = diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
						calls <- request
						writes <- requestHandlerReply(c, request)
					})
				}
				h := parityStartConfigured(t, frontend, true, options)
				request := requestHandlerRequest(h, 700)
				request.Header.CommandFlags |= diam.RetransmittedFlag
				want := uint32(diam.Success)
				switch scenario {
				case "no-route":
					want = diam.CommandUnsupported
				case "unadvertised":
					request.Header.ApplicationID++
					want = diam.ApplicationUnsupported
				case "invalid":
					contractDrop(request, contractRequired)
					want = diam.MissingAVP
				case "decode":
					request.AddAVP(diam.NewAVP(contractRequired, avp.Mbit, 0, datatype.Unknown{1, 2}))
					want = diam.InvalidAVPLength
				}
				header := h.write(t, request)
				if want == diam.Success {
					requestHandlerExactAnswer(t, h, request)
					if got := parityAwait(t, calls); got.Header.CommandFlags&diam.RetransmittedFlag == 0 {
						t.Fatal("handler lost the received T bit")
					}
					if err := parityAwait(t, writes); err != nil {
						t.Fatal(err)
					}
				} else {
					h.answer(t, request, want)
					event := parityAwait(t, h.events)
					if event.Err == nil || event.Err.ResultCode() != want || event.Message.Header != header || event.Reply != diam.ProtocolReplyQueued || event.ReplyCode != want || event.Closing {
						t.Fatalf("request rejection event=%+v; want %d for %+v", event, want, header)
					}
				}
				h.barrier(t)
				h.noEvents(t)
				select {
				case request := <-calls:
					t.Fatalf("rejected request reached handler: %+v", request.Header)
				default:
				}
			})
		}
	})
}

func TestManagerRequestHandlersTCPRegistration(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		h := parityStartConfigured(t, frontend, true, paritySettings{serverConcurrency: concurrency})
		calls := make(chan uint32, 2)
		writes := make(chan error, 2)
		handler := diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			calls <- request.Header.HopByHopID
			writes <- requestHandlerReply(c, request)
		})
		// A registration for a different command exercises an actual mux miss
		// after the Manager's fast path observes that handlers are registered.
		h.manager.HandleIdx(diam.CommandIndex{AppID: contractApp, Code: contractCommand + 1, Request: true}, handler)
		request := requestHandlerRequest(h, 705)
		header := h.write(t, request)
		h.answer(t, request, diam.CommandUnsupported)
		event := parityAwait(t, h.events)
		if event.Err == nil || event.Err.ResultCode() != diam.CommandUnsupported || event.Message.Header != header || event.Reply != diam.ProtocolReplyQueued || event.ReplyCode != diam.CommandUnsupported {
			t.Fatalf("mux-miss disposition=%+v", event)
		}
		h.barrier(t)
		select {
		case id := <-calls:
			t.Fatalf("unmatched command reached handler: %d", id)
		default:
		}
		// Registration after Start applies to a later received message.
		h.manager.HandleIdx(diam.CommandIndex{AppID: contractApp, Code: contractCommand, Request: true}, handler)
		request = requestHandlerRequest(h, 706)
		h.write(t, request)
		requestHandlerExactAnswer(t, h, request)
		if id := parityAwait(t, calls); id != 706 {
			t.Fatalf("late registration handled request %d", id)
		}
		if err := parityAwait(t, writes); err != nil {
			t.Fatal(err)
		}
		h.barrier(t)
		h.noEvents(t)
	})
}

func TestManagerRequestHandlersTCPConnection(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		type observed struct {
			conn   diam.Conn
			meta   *smpeer.Metadata
			notify diam.CloseNotifier
			err    error
		}
		seen := make(chan observed, 1)
		closed := make(chan struct{})
		h := parityStartConfigured(t, frontend, true, paritySettings{serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			if request.Header.HopByHopID == 711 {
				c.Close()
				close(closed)
				return
			}
			meta, _ := smpeer.FromContext(c.Context())
			notify, _ := diam.ConnAs[diam.CloseNotifier](c)
			seen <- observed{c, meta, notify, requestHandlerReply(c, request)}
		})})
		request := requestHandlerRequest(h, 710)
		h.write(t, request)
		requestHandlerExactAnswer(t, h, request)
		got := parityAwait(t, seen)
		if got.err != nil || got.meta == nil || got.meta.OriginHost != "remote.example.net" || got.meta.OriginRealm != "example.net" || got.notify == nil {
			t.Fatalf("handler connection metadata/capabilities=%+v", got)
		}
		if frontend.initiator && (got.meta.CEA == nil || got.meta.CER != nil) || !frontend.initiator && (got.meta.CER == nil || got.meta.CEA != nil) {
			t.Fatalf("peer metadata does not identify the handshake role: %+v", got.meta)
		}
		h.barrier(t)
		h.noEvents(t)
		h.write(t, requestHandlerRequest(h, 711))
		parityAwait(t, closed)
		parityAwait(t, got.notify.CloseNotify())
		h.eof(t)
	})
}

func TestManagerRequestHandlersTCPRefusesRequestWrites(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		errorsSeen := make(chan error, 1)
		h := parityStartConfigured(t, frontend, true, paritySettings{serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			frame, err := request.Serialize()
			if err == nil {
				for _, write := range []func([]byte) (int, error){c.Write, func(b []byte) (int, error) { return c.WriteStream(b, 0) }} {
					n, rejected := write(frame)
					if n != 0 || !errors.Is(rejected, peer.ErrInvalidRequest) {
						err = fmt.Errorf("request write=%d,%v; want zero bytes and ErrInvalidRequest", n, rejected)
						break
					}
				}
			}
			if answerErr := requestHandlerReply(c, request); err == nil {
				err = answerErr
			}
			errorsSeen <- err
		})})
		request := requestHandlerRequest(h, 720)
		h.write(t, request)
		// The first frame must be the answer: a leaked request fails here.
		requestHandlerExactAnswer(t, h, request)
		if err := parityAwait(t, errorsSeen); err != nil {
			t.Fatal(err)
		}
		h.barrier(t)
		h.noEvents(t)
	})
}

func TestManagerRequestHandlersTCPConcurrency(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		const limit = 2
		count := 6
		concurrent := !frontend.initiator && concurrency > 0
		if concurrent {
			count = 10
		}
		started := make(chan uint32, count)
		release := make(chan struct{}, count)
		writes := make(chan error, count)
		var active, maximum atomic.Int32
		h := parityStartConfigured(t, frontend, true, paritySettings{handlerLimit: limit, serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			n := active.Add(1)
			for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
			}
			defer active.Add(-1)
			started <- request.Header.HopByHopID
			<-release
			writes <- requestHandlerReply(c, request)
		})})
		t.Cleanup(func() {
			for range count {
				select {
				case release <- struct{}{}:
				default:
				}
			}
		})
		initial := count
		if concurrent {
			initial = 8
		}
		for i := range initial {
			h.write(t, requestHandlerRequest(h, uint32(800+i)))
		}
		for range limit {
			parityAwait(t, started)
		}
		if concurrent {
			// Two application handlers run and six Server callbacks wait for
			// Manager slots. Server's other two slots still admit a DWR.
			h.barrier(t)
			for i := initial; i < count; i++ {
				h.write(t, requestHandlerRequest(h, uint32(800+i)))
			}
		}
		admitted := int64(limit + 1)
		if concurrent {
			admitted = int64(count)
		}
		requestHandlerAwaitAdmission(t, h, admitted)
		// Sequential dispatch blocks on the first waiting callback. Concurrent
		// Server dispatch stops reading when all eight callbacks are waiting.
		dwr := contractBase(h.dict, diam.DeviceWatchdog, true)
		dwr.Header.HopByHopID = 900
		h.write(t, dwr)
		requestHandlerSilence(t, h)
		select {
		case id := <-started:
			t.Fatalf("request %d exceeded the %d-handler bound", id, limit)
		default:
		}
		for i := range count {
			release <- struct{}{}
			if i < count-limit {
				parityAwait(t, started)
			}
		}
		seen := make(map[uint32]bool, count)
		watchdog := false
		for range count + 1 {
			answer := h.read(t)
			if answer.Header.CommandCode == diam.DeviceWatchdog {
				if watchdog || answer.Header.HopByHopID != dwr.Header.HopByHopID || contractCode(t, answer) != diam.Success {
					t.Fatalf("watchdog answer=%+v", answer)
				}
				watchdog = true
				continue
			}
			id := answer.Header.HopByHopID
			if id < 800 || id >= uint32(800+count) || seen[id] || contractCode(t, answer) != diam.Success || answer.Header.CommandFlags != diam.ProxiableFlag {
				t.Fatalf("unexpected/duplicate application answer=%+v", answer)
			}
			seen[id] = true
		}
		for range count {
			if err := parityAwait(t, writes); err != nil {
				t.Fatal(err)
			}
		}
		if maximum.Load() != limit || len(seen) != count || !watchdog {
			t.Fatalf("maximum=%d replies=%d DWA=%t", maximum.Load(), len(seen), watchdog)
		}
		h.barrier(t)
		h.noEvents(t)
	})
}

func TestManagerRequestHandlersTCPBelowLimit(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		started, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		writes := make(chan error, 2)
		h := parityStartConfigured(t, frontend, true, paritySettings{handlerLimit: 2, serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			if request.Header.HopByHopID == 910 {
				close(started)
				<-release
			}
			writes <- requestHandlerReply(c, request)
		})})
		t.Cleanup(unblock)
		first := requestHandlerRequest(h, 910)
		h.write(t, first)
		parityAwait(t, started)
		// No handler slot is needed for DWR, DWA or an owned application answer.
		h.barrier(t)
		out := h.send()
		outbound := h.read(t)
		h.write(t, outbound.Answer(diam.Success))
		if result := parityAwait(t, out); result.err != nil || result.answer == nil || contractCode(t, result.answer) != diam.Success {
			t.Fatalf("owned answer blocked behind handler: %+v", result)
		}
		second := requestHandlerRequest(h, 911)
		h.write(t, second)
		requestHandlerExactAnswer(t, h, second)
		unblock()
		requestHandlerExactAnswer(t, h, first)
		for range 2 {
			if err := parityAwait(t, writes); err != nil {
				t.Fatal(err)
			}
		}
		h.barrier(t)
		h.noEvents(t)
	})
}

func TestManagerRequestHandlersTCPDefaultLimit(t *testing.T) {
	for _, configured := range []int{0, -1} {
		t.Run(fmt.Sprintf("configured=%d", configured), func(t *testing.T) {
			const limit = 64
			started := make(chan struct{}, limit+1)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			h := parityStartConfigured(t, parityFrontend{name: "ManagerDialed", manager: true, initiator: true}, true, paritySettings{handlerLimit: configured, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
				started <- struct{}{}
				<-release
				_ = requestHandlerReply(c, request)
			})})
			t.Cleanup(unblock)
			for i := range limit + 1 {
				h.write(t, requestHandlerRequest(h, uint32(1000+i)))
			}
			for range limit {
				parityAwait(t, started)
			}
			requestHandlerAwaitAdmission(t, h, limit+1)
			dwr := contractBase(h.dict, diam.DeviceWatchdog, true)
			h.write(t, dwr)
			requestHandlerSilence(t, h)
			select {
			case <-started:
				t.Fatal("default allowed more than 64 handlers")
			default:
			}
			unblock()
			parityAwait(t, started)
			for range limit + 2 {
				answer := h.read(t)
				if contractCode(t, answer) != diam.Success {
					t.Fatalf("drained answer=%v", answer)
				}
			}
			h.barrier(t)
			h.noEvents(t)
		})
	}
}

func TestManagerRequestHandlersTCPClosing(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
				started, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				calls := make(chan uint32, 4)
				writes := make(chan error, 1)
				h := parityStartConfigured(t, frontend, true, paritySettings{serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
					calls <- request.Header.HopByHopID
					close(started)
					<-release
					writes <- requestHandlerReply(c, request)
				})})
				t.Cleanup(unblock)
				first := requestHandlerRequest(h, 1200)
				h.write(t, first)
				parityAwait(t, started)
				parityAwait(t, calls)
				var closing <-chan error
				var ownDPR *diam.Message
				if local {
					closing = h.close()
					ownDPR = h.read(t)
					if ownDPR.Header.CommandCode != diam.DisconnectPeer || ownDPR.Header.CommandFlags&diam.RequestFlag == 0 {
						t.Fatalf("local shutdown message=%+v", ownDPR)
					}
				}
				crossed := contractBase(h.dict, diam.DisconnectPeer, true)
				h.write(t, crossed)
				h.answer(t, crossed, diam.UnableToComply)
				// Closing suppresses new work but an existing handler may still
				// write its answer before the transport closes.
				h.write(t, requestHandlerRequest(h, 1201))
				// A later DPR fences the discarded request before checking that
				// no new handler ran. Wire silence alone cannot order admission.
				crossed.Header.HopByHopID++
				crossed.Header.EndToEndID++
				h.write(t, crossed)
				h.answer(t, crossed, diam.UnableToComply)
				requestHandlerSilence(t, h)
				select {
				case id := <-calls:
					t.Fatalf("Closing request %d reached handler", id)
				default:
				}
				unblock()
				requestHandlerExactAnswer(t, h, first)
				if err := parityAwait(t, writes); err != nil {
					t.Fatal(err)
				}
				// A later DPR fences completion of the preceding application write.
				// The handler accounting drains before the new DPR is evaluated.
				crossed.Header.HopByHopID++
				crossed.Header.EndToEndID++
				for {
					h.write(t, crossed)
					answer := h.read(t)
					if answer.Header.CommandCode != diam.DisconnectPeer || answer.Header.HopByHopID != crossed.Header.HopByHopID {
						t.Fatalf("drain probe answer=%+v", answer)
					}
					if contractCode(t, answer) == diam.Success {
						break
					}
					if contractCode(t, answer) != diam.UnableToComply {
						t.Fatalf("drain probe Result-Code=%d", contractCode(t, answer))
					}
				}
				if local {
					h.write(t, requestHandlerDPA(h, ownDPR))
					if err := parityAwait(t, closing); err != nil {
						t.Fatal(err)
					}
					h.eof(t)
				}
				h.noEvents(t)
			})
		}
	})
}

func TestManagerRequestHandlersTCPCloseWaits(t *testing.T) {
	for _, scenario := range []string{"wait", "context", "from-handler"} {
		t.Run(scenario, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			conn := make(chan diam.Conn, 1)
			closed := make(chan error, 1)
			managerReady := make(chan *peer.Manager, 1)
			h := parityStartConfigured(t, parityFrontend{name: "ManagerDialed", manager: true, initiator: true}, true, paritySettings{requestHandler: diam.HandlerFunc(func(c diam.Conn, _ *diam.Message) {
				conn <- c
				close(started)
				if scenario == "from-handler" {
					manager := <-managerReady
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						closed <- manager.Close(ctx, sm.DisconnectRebooting)
					}()
				}
				<-release
			})})
			manager := h.manager
			managerReady <- manager
			t.Cleanup(unblock)
			h.write(t, requestHandlerRequest(h, 1300))
			parityAwait(t, started)
			if scenario != "from-handler" {
				go func() {
					timeout := 10 * time.Second
					if scenario == "context" {
						timeout = 100 * time.Millisecond
					}
					ctx, cancel := context.WithTimeout(context.Background(), timeout)
					defer cancel()
					closed <- manager.Close(ctx, sm.DisconnectRebooting)
				}()
			}
			dpr := h.read(t)
			if dpr.Header.CommandCode != diam.DisconnectPeer {
				t.Fatalf("Close did not initiate DPR immediately: %+v", dpr)
			}
			h.write(t, requestHandlerDPA(h, dpr))
			h.eof(t)
			if scenario == "context" {
				if err := parityAwait(t, closed); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("bounded Close=%v; want DeadlineExceeded", err)
				}
			} else {
				select {
				case err := <-closed:
					t.Fatalf("Close completed with handler still running: %v", err)
				default:
				}
			}
			// The handler's answer capability observes transport closure.
			c := parityAwait(t, conn)
			if _, err := requestHandlerAnswer(requestHandlerRequest(h, 1300)).WriteTo(c); err == nil {
				t.Fatal("answer after transport closure succeeded")
			}
			unblock()
			if scenario != "context" {
				if err := parityAwait(t, closed); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
				t.Fatalf("Close after handler completion=%v", err)
			}
		})
	}
}

func TestManagerRequestHandlersTCPPanic(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		h := parityStartConfigured(t, frontend, true, paritySettings{handlerLimit: 1, serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
			if request.Header.HopByHopID == 1400 {
				panic("handler-test-panic")
			}
			_ = requestHandlerReply(c, request)
		})})
		h.write(t, requestHandlerRequest(h, 1400))
		// The one slot becomes usable after recovery. If recovery closes the
		// connection, writes an answer, or leaks the slot, this answer fails.
		next := requestHandlerRequest(h, 1401)
		h.write(t, next)
		requestHandlerExactAnswer(t, h, next)
		h.barrier(t)
		records := h.logs.RecordsWithMessage("peer: panic in request handler")
		if len(records) != 1 || records[0].Level != slog.LevelError || logtest.Attr(records[0], "peer_host").String() != "remote.example.net" || logtest.Attr(records[0], "panic").String() != "handler-test-panic" || logtest.Attr(records[0], "stack").String() == "" || !logtest.HasAttr(records[0], "message") {
			t.Fatalf("panic logs=%+v", records)
		}
		h.noEvents(t)
	})
}

func TestManagerRequestHandlersTCPSlotWaitClose(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		for _, cause := range []string{"local", "manager"} {
			t.Run(cause, func(t *testing.T) {
				started := make(chan diam.Conn, 1)
				release := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var calls atomic.Int32
				h := parityStartConfigured(t, frontend, true, paritySettings{handlerLimit: 1, serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, _ *diam.Message) {
					calls.Add(1)
					started <- c
					<-release
				})})
				t.Cleanup(unblock)
				h.write(t, requestHandlerRequest(h, 1500))
				c := parityAwait(t, started)
				waiting := 1
				for i := range waiting {
					h.write(t, requestHandlerRequest(h, uint32(1501+i)))
				}
				requestHandlerAwaitAdmission(t, h, int64(1+waiting))
				var closing <-chan error
				if cause == "local" {
					c.Close()
				} else {
					ctx, cancel := context.WithCancel(context.Background())
					result := make(chan error, 1)
					closing = result
					go func() { result <- h.manager.Close(ctx, sm.DisconnectRebooting) }()
					dpr := h.read(t)
					if dpr.Header.CommandCode != diam.DisconnectPeer {
						t.Fatalf("Close sent %+v", dpr)
					}
					// Context cancellation force-closes transport even while all callback
					// slots are occupied and a DPA cannot be admitted by the reader.
					cancel()
					if err := parityAwait(t, closing); !errors.Is(err, context.Canceled) {
						t.Fatalf("bounded Close=%v", err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				for n := len(h.logs.Records()) + 1; ; n++ {
					if len(h.logs.RecordsWithMessage("peer: request handler dropped; connection closed")) == waiting {
						break
					}
					if _, err := h.logs.Wait(ctx, n); err != nil {
						t.Fatal("slot waiters did not wake on closure", err)
					}
				}
				unblock()
				closing = h.close()
				if err := parityAwait(t, closing); err != nil {
					t.Fatalf("Close after slot-wait drop=%v", err)
				}
				if calls.Load() != 1 {
					t.Fatalf("closed slot waiter ran handler; calls=%d", calls.Load())
				}
				records := h.logs.RecordsWithMessage("peer: request handler dropped; connection closed")
				if len(records) != waiting {
					t.Fatalf("drop logs=%+v; want %d", records, waiting)
				}
				for _, record := range records {
					if record.Level != slog.LevelWarn {
						t.Fatalf("drop level=%v", record.Level)
					}
				}
				// Canceling Close's context may report its existing disconnect
				// timeout. Dropping an application callback adds no event.
				for {
					select {
					case event := <-h.events:
						if cause != "manager" || event.Err == nil || event.Err.Kind() != diam.ProtocolDisconnectTimeout || !event.Closing || event.Message.HasHeader || event.Reply != diam.ProtocolReplyNone {
							t.Fatalf("slot-wait closure event=%+v", event)
						}
					default:
						return
					}
				}
			})
		}
	})
}

func TestManagerRequestHandlersTCPWaitingRequestBeforeFIN(t *testing.T) {
	for _, frontend := range parityFrontends {
		if !frontend.manager {
			continue
		}
		t.Run(frontend.name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int32
			h := parityStartConfigured(t, frontend, true, paritySettings{handlerLimit: 1, requestHandler: diam.HandlerFunc(func(_ diam.Conn, request *diam.Message) {
				calls.Add(1)
				if request.Header.HopByHopID == 1600 {
					close(started)
					<-release
				}
			})})
			t.Cleanup(unblock)
			h.write(t, requestHandlerRequest(h, 1600))
			parityAwait(t, started)
			h.write(t, requestHandlerRequest(h, 1601))
			requestHandlerAwaitAdmission(t, h, 2)
			if err := h.wire.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			// A FIN after the queued request cannot overtake that request's
			// delivery and close the session while its callback is waiting.
			requestHandlerSilence(t, h)
			unblock()
			h.eof(t)
			if err := parityAwait(t, h.close()); err != nil {
				t.Fatalf("Close after FIN and released slot=%v", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("FIN overtook the waiting request; calls=%d", calls.Load())
			}
			h.noEvents(t)
		})
	}
}

func TestManagerRequestHandlersTCPAnswerBeforeFIN(t *testing.T) {
	requestHandlerFrontends(t, func(t *testing.T, frontend parityFrontend, concurrency int) {
		h := parityStartConfigured(t, frontend, true, paritySettings{serverConcurrency: concurrency, requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) { _ = requestHandlerReply(c, request) })})
		// Serving one registered request activates any request-dispatch lifecycle
		// hooks before the final owned application answer arrives.
		request := requestHandlerRequest(h, 1700)
		h.write(t, request)
		requestHandlerExactAnswer(t, h, request)
		h.barrier(t)
		pending := h.send()
		outbound := h.read(t)
		h.write(t, outbound.Answer(diam.Success))
		if err := h.wire.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		result := parityAwait(t, pending)
		if result.err != nil || result.answer == nil || result.answer.Header.HopByHopID != outbound.Header.HopByHopID || result.answer.Header.EndToEndID != outbound.Header.EndToEndID || contractCode(t, result.answer) != diam.Success {
			t.Fatalf("FIN discarded preceding answer: %+v", result)
		}
		h.eof(t)
		if err := parityAwait(t, h.close()); err != nil {
			t.Fatalf("Close after drained answer and FIN=%v", err)
		}
		h.noEvents(t)
	})
}

func requestHandlerDPA(h *parityTCP, request *diam.Message) *diam.Message {
	answer := contractBase(h.dict, diam.DisconnectPeer, false)
	answer.Header.HopByHopID, answer.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
	return answer
}

func requestHandlerReply(c diam.Conn, request *diam.Message) error {
	_, err := requestHandlerAnswer(request).WriteTo(c)
	return err
}

func requestHandlerRequest(h *parityTCP, id uint32) *diam.Message {
	request := contractRequest(h.dict)
	request.Header.HopByHopID, request.Header.EndToEndID = id, id+1000
	request.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(fmt.Sprintf("remote.example.net;%d", id))))
	return request
}

func requestHandlerExactAnswer(t *testing.T, h *parityTCP, request *diam.Message) []byte {
	t.Helper()
	got := h.answer(t, request, diam.Success)
	want, err := requestHandlerAnswer(request).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("handler answer bytes=%x; want=%x", got, want)
	}
	return got
}

func TestProtocolTCPParityRequestHandler(t *testing.T) {
	var baseline []byte
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			writes := make(chan error, 1)
			h := parityStartConfigured(t, frontend, true, paritySettings{requestHandler: diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
				writes <- requestHandlerReply(c, request)
			})})
			request := requestHandlerRequest(h, 600)
			h.write(t, request)
			got := requestHandlerExactAnswer(t, h, request)
			if err := parityAwait(t, writes); err != nil {
				t.Fatal(err)
			}
			if baseline == nil {
				baseline = got
			} else if !bytes.Equal(got, baseline) {
				t.Fatalf("handler answer differs from StateMachine: got=%x want=%x", got, baseline)
			}
			h.barrier(t)
			h.noEvents(t)
		})
	}
}
