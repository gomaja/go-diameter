package peer_test

import (
	"bytes"
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
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
)

// The public Manager clock supplies receipt times and records actual scheduled
// deadlines. No peer state or protocol input is manufactured by this clock.
type parityClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*parityTimer
	changed chan struct{}
}

type parityTimer struct {
	clock    *parityClock
	deadline time.Time
	fire     func()
	active   bool
}

func (c *parityClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now.IsZero() {
		c.now = time.Unix(1700000000, 0)
	}
	return c.now
}

func (c *parityClock) AfterFunc(d time.Duration, f func()) peer.Timer {
	now := c.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &parityTimer{clock: c, deadline: now.Add(d), fire: f, active: true}
	c.timers = append(c.timers, timer)
	if c.changed == nil {
		c.changed = make(chan struct{}, 1)
	}
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return timer
}

func (timer *parityTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	was := timer.active
	timer.active = false
	return was
}

func (c *parityClock) current(t *testing.T) *parityTimer {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		var next *parityTimer
		for _, timer := range c.timers {
			if timer.active && (next == nil || timer.deadline.Before(next.deadline)) {
				next = timer
			}
		}
		if c.changed == nil {
			c.changed = make(chan struct{}, 1)
		}
		changed := c.changed
		c.mu.Unlock()
		if next != nil {
			return next
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("no scheduled protocol deadline")
			return nil
		}
	}
}

func (c *parityClock) advance(d time.Duration) {
	c.Now()
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *parityClock) expire(t *testing.T) {
	t.Helper()
	timer := c.current(t)
	c.mu.Lock()
	c.now, timer.active = timer.deadline, false
	c.mu.Unlock()
	timer.fire()
}

func (h *parityTCP) connection(t *testing.T) diam.Conn {
	t.Helper()
	if h.conn == nil {
		message := contractBase(h.dict, diam.DisconnectPeer, false)
		header := h.write(t, message)
		h.event(t, header, h.frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))
	}
	return h.conn
}

func (h *parityTCP) callback(t *testing.T, message *diam.Message, description *diam.MessageError) {
	t.Helper()
	conn := h.connection(t)
	if err := h.handler.HandleMessageError(conn, message, description); err != nil {
		t.Fatal(err)
	}
}

func (h *parityTCP) callbackEvent(t *testing.T, message *diam.Message, want parityDisposition) {
	t.Helper()
	event := parityAwait(t, h.events)
	if event.Conn != h.conn || !event.Message.HasHeader || event.Message.Header != *message.Header || event.Message.Stream != message.MessageStream() {
		t.Fatalf("callback metadata=%+v; want %+v stream %d", event, message.Header, message.MessageStream())
	}
	got := parityDisposition{event.Err.Kind(), event.Err.ResultCode(), event.Closing, event.Reply, event.ReplyCode}
	if got != want {
		t.Fatalf("callback disposition=%+v; want %+v", got, want)
	}
}

func parityBodyError() *diam.MessageError {
	return &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true,
		FailedAVP: diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}), Err: errors.New("invalid AVP payload")}
}

func TestProtocolTCPParityInitialHeaderDiagnosis(t *testing.T) {
	for _, callback := range []bool{false, true} {
		for _, frontend := range parityFrontends {
			if frontend.initiator {
				continue
			}
			t.Run(fmt.Sprintf("callback=%t/%s", callback, frontend.name), func(t *testing.T) {
				h := parityStart(t, frontend, false)
				message := contractBase(h.dict, diam.DeviceWatchdog, true)
				message.Header.CommandFlags |= diam.ProxiableFlag
				code := uint32(diam.InvalidHDRBits)
				if callback {
					code = diam.InvalidAVPLength
					h.callback(t, message, parityBodyError())
					h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolHandshakeState, code, false, true))
				} else {
					header := h.write(t, message)
					h.event(t, header, frontend.replyDisposition(diam.ProtocolHandshakeState, code, false, true))
				}
				h.eof(t)
				h.noEvents(t)
			})
		}
	}
}

func TestProtocolTCPParityFatalRepeatedCER(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			var ceaCalls atomic.Int32
			options := paritySettings{}
			if !frontend.manager {
				options.onCEA = func(diam.Conn, *diam.Message) { ceaCalls.Add(1) }
			}
			h := parityStartConfigured(t, frontend, true, options)
			before := ceaCalls.Load()
			message := contractBase(h.dict, diam.CapabilitiesExchange, true)
			h.callback(t, message, parityBodyError())
			h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, true))
			if !frontend.manager && ceaCalls.Load() != before+1 {
				t.Fatalf("required error CEA invoked OnCEA %d times; want one", ceaCalls.Load()-before)
			}
			wire := h.answer(t, message, diam.InvalidAVPLength)
			answer, err := diam.ReadMessage(bytes.NewReader(wire), h.dict)
			if err != nil {
				t.Fatal(err)
			}
			if answer.Header.CommandFlags&diam.ErrorFlag != 0 {
				t.Fatal("permanent error used E-bit grammar")
			}
			failed, err := answer.FindAVP(avp.FailedAVP, 0)
			if err != nil {
				t.Fatal("invalid-length answer lost Failed-AVP", err)
			}
			group, ok := failed.Data.(*diam.GroupedAVP)
			if !ok || len(group.AVP) != 1 || group.AVP[0].Code != avp.InbandSecurityID {
				t.Fatalf("Failed-AVP=%+v", failed)
			}
			if frontend.manager {
				h.barrier(t)
			} else {
				h.eof(t)
			}
			h.noEvents(t)
		})
	}
}

func TestProtocolTCPParityHeaderDecoderFatality(t *testing.T) {
	for _, request := range []bool{false, true} {
		for _, frontend := range parityFrontends {
			t.Run(fmt.Sprintf("request=%t/%s", request, frontend.name), func(t *testing.T) {
				h := parityStart(t, frontend, true)
				message := contractBase(h.dict, diam.DeviceWatchdog, request)
				message.Header.CommandFlags |= diam.ProxiableFlag
				h.callback(t, message, parityBodyError())
				if request {
					h.answer(t, message, diam.InvalidHDRBits)
				}
				h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolInvalidHeader, diam.InvalidHDRBits, request, true))
				found := false
				for _, record := range h.logs.Records() {
					cause, ok := logtest.Attr(record, "error").Any().(*diam.MessageError)
					if ok && cause.ResultCode == diam.InvalidHDRBits {
						found = true
						if !cause.Fatal {
							t.Fatal("header diagnosis erased decoder fatality")
						}
					}
				}
				if !found {
					t.Fatal("header diagnostic lost its typed error")
				}
				if frontend.manager {
					h.barrier(t)
				} else {
					h.eof(t)
				}
				h.noEvents(t)
			})
		}
	}
}

func TestProtocolTCPParityClosingDecoderFatality(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true)
			h.connection(t)
			done := h.close()
			local := h.read(t)
			message := contractBase(h.dict, diam.DisconnectPeer, true)
			h.callback(t, message, parityBodyError())
			h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolMalformedMessage, diam.InvalidAVPLength, false, true))
			crossed := contractBase(h.dict, diam.DisconnectPeer, true)
			h.write(t, crossed)
			h.answer(t, crossed, diam.Success)
			h.answerPeer(t, local)
			if err := parityAwait(t, done); err != nil {
				t.Fatal(err)
			}
			h.eof(t)
			h.noEvents(t)
		})
	}
}

func TestProtocolTCPParityClosingHeaderDiagnosis(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true)
			h.connection(t)
			done := h.close()
			local := h.read(t)
			message := contractBase(h.dict, diam.DisconnectPeer, true)
			message.Header.CommandFlags |= diam.ProxiableFlag
			h.callback(t, message, &diam.MessageError{ResultCode: diam.MissingAVP})
			h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolInvalidHeader, diam.InvalidHDRBits, false, false))
			found := false
			for _, record := range h.logs.Records() {
				cause, ok := logtest.Attr(record, "error").Any().(*diam.MessageError)
				if ok && cause.ResultCode == diam.InvalidHDRBits {
					found = true
				}
			}
			if !found {
				t.Fatal("header cause was not logged")
			}
			crossed := contractBase(h.dict, diam.DisconnectPeer, true)
			h.write(t, crossed)
			h.answer(t, crossed, diam.Success)
			h.answerPeer(t, local)
			if err := parityAwait(t, done); err != nil {
				t.Fatal(err)
			}
			h.eof(t)
			h.noEvents(t)
		})
	}
}

func TestProtocolTCPParityFatalBodyReceipt(t *testing.T) {
	for _, frontend := range parityFrontends {
		if frontend.manager {
			continue
		}
		t.Run(frontend.name, func(t *testing.T) {
			t.Parallel()
			parityNativeFatalBodyReceipt(t, frontend)
		})
	}
	for _, frontend := range parityFrontends {
		if !frontend.manager {
			continue
		}
		t.Run(frontend.name, func(t *testing.T) {
			clock := new(parityClock)
			h := parityStartConfigured(t, frontend, true, paritySettings{clock: clock})
			h.connection(t)
			h.barrier(t)
			clock.expire(t)
			probe := h.read(t)
			if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatal("watchdog did not publish DWR")
			}
			clock.expire(t)
			for parityAwait(t, h.peers).Peer.Watchdog != peer.WatchdogSuspect {
			}
			before := clock.current(t)
			clock.advance(10 * time.Second)
			message := contractBase(h.dict, diam.DeviceWatchdog, true)
			h.callback(t, message, parityBodyError())
			h.answer(t, message, diam.InvalidAVPLength)
			h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, true))
			after := clock.current(t)
			if after == before || !after.deadline.After(before.deadline) {
				t.Fatal("fatal body receipt did not rearm Tw from receipt")
			}
			if state := h.manager.Peers()[0].Watchdog; state != peer.WatchdogSuspect {
				t.Fatalf("invalid receipt changed health to %s", state)
			}
			h.answerPeer(t, probe)
			for parityAwait(t, h.peers).Peer.Watchdog != peer.WatchdogOkay {
			}
			h.barrier(t)
			h.noEvents(t)
		})
	}
}

// Holding the native transport writer exposes the interval between selecting
// a required fatal reply and completing it. The connection and reader are real
// TCP; only the selected answer's write is delayed.
type parityReplyGate struct {
	armed, entered, release chan struct{}
	once                    sync.Once
}

type parityReplyConn struct {
	net.Conn
	gate *parityReplyGate
}

func (c *parityReplyConn) Write(wire []byte) (int, error) {
	select {
	case <-c.gate.armed:
		header, err := diam.DecodeHeader(wire)
		if err == nil && header.CommandCode == diam.DeviceWatchdog && header.CommandFlags&diam.RequestFlag == 0 {
			c.gate.once.Do(func() { close(c.gate.entered) })
			<-c.gate.release
		}
	default:
	}
	return c.Conn.Write(wire)
}

type parityReplyListener struct {
	net.Listener
	gate *parityReplyGate
}

func (l *parityReplyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &parityReplyConn{Conn: conn, gate: l.gate}, nil
}

func parityNativeFatalBodyReceipt(t *testing.T, frontend parityFrontend) {
	t.Helper()
	gate := &parityReplyGate{armed: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	h := parityStartConfigured(t, frontend, true, paritySettings{interval: 12 * time.Second, writeGate: gate})
	h.barrier(t)
	// Native watchdogs use the public interval with its production ±2s jitter.
	// A 20s boundary includes the maximum 14s Tw without shortening policy.
	if err := h.wire.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	probe, err := diam.ReadMessage(h.wire, h.dict)
	if err != nil {
		t.Fatal(err)
	}
	if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatal("watchdog did not publish DWR")
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for suspect := false; !suspect; {
		select {
		case event := <-h.watchdog:
			suspect = event == sm.WatchdogSuspect
		case <-deadline.C:
			t.Fatal("watchdog did not become SUSPECT with its DWR pending")
		}
	}
	time.Sleep(8 * time.Second)
	close(gate.armed)
	message := contractBase(h.dict, diam.DeviceWatchdog, true)
	callback := make(chan error, 1)
	receipt := time.Now()
	go func() { callback <- h.handler.HandleMessageError(h.conn, message, parityBodyError()) }()
	parityAwait(t, gate.entered)
	// Original Tw must have expired by 14s from SUSPECT. The replacement
	// cannot expire before 10s from this receipt. At 8+8s only a reset survives.
	time.Sleep(time.Until(receipt.Add(8 * time.Second)))
	if elapsed := time.Since(receipt); elapsed >= 10*time.Second {
		t.Fatalf("timer observation missed the receipt window: %s", elapsed)
	}
	if h.conn.Closed() {
		t.Fatal("fatal valid-header receipt did not replace the old Tw before the required reply")
	}
	tracker, ok := diam.ConnAs[interface{ PendingRequests() *diam.PendingRequests }](h.conn)
	if !ok || !tracker.PendingRequests().HasPending() {
		t.Fatal("invalid fatal receipt credited the outstanding DWR")
	}
	select {
	case event := <-h.watchdog:
		t.Fatalf("invalid receipt changed watchdog health: %s", event)
	default:
	}
	release()
	h.answer(t, message, diam.InvalidAVPLength)
	if err := parityAwait(t, callback); err != nil {
		t.Fatal(err)
	}
	h.callbackEvent(t, message, frontend.replyDisposition(diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, true))
	h.eof(t)
	// Completion disposes the refreshed Tw; neither it nor a stale expiry
	// may publish a watchdog observation after fatal transport closure.
	time.Sleep(15 * time.Second)
	select {
	case event := <-h.watchdog:
		t.Fatalf("fatal completion left a watchdog callback active: %s", event)
	default:
	}
	h.noEvents(t)
}

// In-tree body decoders report recoverable errors. Fatal valid-header body
// errors therefore exercise the public direct-callback contract here; they do
// not run the native reader's independent fatal-error closure path.
func TestProtocolTCPParityUncorrelatedFatalCEA(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		for _, coordinate := range []string{"hop", "end"} {
			for _, frontend := range parityFrontends {
				if !frontend.initiator {
					continue
				}
				t.Run(fmt.Sprintf("direct-callback/fatal=%t/%s/%s", fatal, coordinate, frontend.name), func(t *testing.T) {
					options := paritySettings{}
					if frontend.manager {
						options.clock = new(parityClock)
					}
					h := parityStartConfigured(t, frontend, false, options)
					cer := h.read(t)
					answer := contractBase(h.dict, diam.CapabilitiesExchange, false)
					answer.Header.HopByHopID, answer.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
					if coordinate == "hop" {
						answer.Header.HopByHopID++
					} else {
						answer.Header.EndToEndID++
					}
					header := h.write(t, answer)
					h.event(t, header, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, false))
					var deadline *parityTimer
					if options.clock != nil {
						deadline = options.clock.current(t)
					}
					description := parityBodyError()
					description.Fatal = fatal
					h.callback(t, answer, description)
					h.callbackEvent(t, answer, frontend.replyDisposition(diam.ProtocolUnexpectedMessage, 0, false, fatal))
					select {
					case <-h.ready:
						t.Fatal("unowned error admitted connection")
					default:
					}
					if fatal {
						if frontend.manager {
							if options.clock.current(t) != deadline || h.conn.Closed() {
								t.Fatal("direct Manager callback took reader-owned closure or replaced CER deadline")
							}
							// A direct invocation has no reader to close the transport.
							h.conn.Close()
						} else if err := parityAwait(t, h.done); err == nil {
							t.Fatal("fatal callback completed Client handshake successfully")
						}
						h.eof(t)
						h.noEvents(t)
						return
					}
					// Recoverable unmatched reports preserve ownership and the deadline.
					if options.clock != nil && options.clock.current(t) != deadline {
						t.Fatal("uncorrelated body error replaced the CER deadline")
					}
					answer.Header.HopByHopID, answer.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
					h.write(t, answer)
					parityAwait(t, h.ready)
					if h.done != nil {
						if err := parityAwait(t, h.done); err != nil {
							t.Fatal(err)
						}
					}
					h.barrier(t)
					h.noEvents(t)
				})
			}
		}
	}
}

func TestProtocolTCPParityOwnedDWAIdentity(t *testing.T) {
	for _, identity := range []uint32{avp.OriginHost, avp.OriginRealm} {
		for _, frontend := range parityFrontends {
			t.Run(fmt.Sprintf("%d/%s", identity, frontend.name), func(t *testing.T) {
				t.Parallel()
				options := paritySettings{probe: true}
				if frontend.manager {
					options.clock = new(parityClock)
				}
				h := parityStartConfigured(t, frontend, true, options)
				if options.clock != nil {
					h.barrier(t)
					options.clock.expire(t)
				}
				probe := h.read(t)
				if probe.Header.CommandCode != diam.DeviceWatchdog || probe.Header.CommandFlags&diam.RequestFlag == 0 {
					t.Fatalf("probe=%+v", probe.Header)
				}
				answer := contractBase(h.dict, diam.DeviceWatchdog, false)
				answer.Header.HopByHopID, answer.Header.EndToEndID = probe.Header.HopByHopID, probe.Header.EndToEndID
				contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(diam.UnableToComply)
				field := contractField(t, answer, identity)
				original := field.Data
				field.Data = datatype.DiameterIdentity("other.example.net")
				header := h.write(t, answer)
				h.event(t, header, frontend.replyDisposition(diam.ProtocolInvalidDWA, 0, false, false))
				field.Data = original
				contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(diam.Success)
				h.write(t, answer)
				if !frontend.manager {
					for parityAwait(t, h.watchdog) != sm.WatchdogAnswerReceived {
					}
				}
				h.barrier(t)
				h.noEvents(t)
			})
		}
	}
}

func TestProtocolTCPParityRequiredReplyBuildFailure(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true)
			h.connection(t)
			empty, err := dict.NewParser()
			if err != nil {
				t.Fatal(err)
			}
			message := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 17, 18, empty)
			h.callback(t, message, &diam.MessageError{ResultCode: diam.InvalidAVPValue, Err: errors.New("invalid AVP payload")})
			h.callbackEvent(t, message, parityDisposition{Kind: diam.ProtocolMalformedMessage, Code: diam.InvalidAVPValue, Closing: true, Reply: diam.ProtocolReplyFailed, ReplyCode: diam.InvalidAVPValue})
			h.eof(t)
			h.noEvents(t)
			found := false
			for _, record := range h.logs.Records() {
				if record.Level != slog.LevelError {
					continue
				}
				found = true
				if frontend.manager {
					cause := logtest.Attr(record, "error").Any()
					if fmt.Sprintf("%T", cause) != "*fmt.wrapError" {
						t.Fatalf("builder failure cause=%T, want standard wrapped error", cause)
					}
				}
			}
			if !found {
				t.Fatal("required reply failure was not logged")
			}
		})
	}
}

func TestProtocolTCPParityLocalDisconnectCause(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true)
			h.connection(t)
			for _, cause := range []uint32{3, ^uint32(0)} {
				err := parityAwait(t, h.closeCause(cause))
				if err == nil || err.Error() != fmt.Sprintf("invalid Disconnect-Cause %d", cause) || fmt.Sprintf("%T", err) != "*errors.errorString" {
					t.Fatalf("invalid cause returned %v", err)
				}
				h.barrier(t)
				h.noEvents(t)
			}
			done := h.close()
			dpr := h.read(t)
			if cause := contractField(t, dpr, avp.DisconnectCause).Data; cause != datatype.Enumerated(sm.DisconnectRebooting) {
				t.Fatalf("DPR cause=%v", cause)
			}
			h.answerPeer(t, dpr)
			if err := parityAwait(t, done); err != nil {
				t.Fatal(err)
			}
			h.eof(t)
			for _, cause := range []uint32{3, ^uint32(0)} {
				err := parityAwait(t, h.closeCause(cause))
				if err == nil || err.Error() != fmt.Sprintf("invalid Disconnect-Cause %d", cause) || fmt.Sprintf("%T", err) != "*errors.errorString" {
					t.Fatalf("invalid cause on closed connection returned %v", err)
				}
			}
			h.noEvents(t)
		})
	}
}

func (h *parityTCP) answerPeer(t *testing.T, request *diam.Message) {
	t.Helper()
	answer := contractBase(h.dict, request.Header.CommandCode, false)
	answer.Header.HopByHopID, answer.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
	h.write(t, answer)
}
