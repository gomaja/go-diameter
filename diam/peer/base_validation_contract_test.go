package peer_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

const contractApp uint32 = 4242
const contractCommand uint32 = 838
const contractRequired uint32 = 70000
const contractGroup uint32 = 70001
const contractChild uint32 = 70002
const contractUnknown uint32 = 0x00fedcba

// This synthetic application isolates request validation from application logic.
const contractXML = `<diameter><application id="4242" name="Contract">
<command code="838" name="Contract" short="CT"><request proxiable="true">
<rule avp="Required" required="true" max="1"/><rule avp="Group" max="1"/><rule avp="AVP"/>
</request><answer proxiable="true"><rule avp="Result-Code" required="true" max="1"/><rule avp="AVP"/></answer></command>
<avp name="Required" code="70000" must="M" must-not="V"><data type="Unsigned32"/></avp>
<avp name="Group" code="70001" must="M" must-not="V"><data type="Grouped"><rule avp="Child" required="true" max="1"/><rule avp="AVP"/></data></avp>
<avp name="Child" code="70002" must="M" must-not="V"><data type="Unsigned32"/></avp>
</application></diameter>`

func contractDict(t *testing.T) *dict.Parser {
	t.Helper()
	d, err := dict.New(dict.Base())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(contractXML)); err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(strings.Replace(contractXML, `id="4242"`, `id="4243"`, 1))); err != nil {
		t.Fatal(err)
	}
	return d
}

func contractSettings(d *dict.Parser, mandatory, validate bool) sm.Settings {
	return sm.Settings{OriginHost: "local.example.net", OriginRealm: "example.net", VendorID: 1, ProductName: "contract", Dict: d,
		HostIPAddresses:            []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))},
		AuthApplicationID:          []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(contractApp))},
		RejectUnknownMandatoryAVPs: mandatory, ValidateRequests: validate}
}

type contractHarness struct {
	conn       net.Conn
	dict       *dict.Parser
	events     chan diam.ProtocolErrorEvent
	calls      atomic.Int32
	disconnect func() <-chan error
}

func contractWrite(t *testing.T, c net.Conn, m *diam.Message) {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Serialize permits deliberately malformed protocol messages.
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}
func contractRead(t *testing.T, h *contractHarness) *diam.Message {
	t.Helper()
	if err := h.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	m, err := diam.ReadMessage(h.conn, h.dict)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func contractCode(t *testing.T, m *diam.Message) uint32 {
	t.Helper()
	a, err := m.FindAVP(avp.ResultCode, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := a.Data.(datatype.Unsigned32)
	if !ok {
		t.Fatalf("Result-Code type %T", a.Data)
	}
	return uint32(n)
}
func contractEvent(t *testing.T, h *contractHarness, request *diam.Message, result uint32) diam.ProtocolErrorEvent {
	t.Helper()
	select {
	case e := <-h.events:
		if e.Err == nil || e.Err.ResultCode() != result || !e.Message.HasHeader || e.Message.Header.HopByHopID != request.Header.HopByHopID || e.Message.Header.EndToEndID != request.Header.EndToEndID {
			t.Fatalf("protocol event=%+v, want result %d for %+v", e, result, request.Header)
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("missing typed protocol event")
	}
	return diam.ProtocolErrorEvent{}
}

func contractBase(d *dict.Parser, command uint32, request bool) *diam.Message {
	flags := uint8(0)
	if request {
		flags = diam.RequestFlag
	}
	m := diam.NewMessage(command, flags, 0, 0x11223344, 0x55667788, d)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("remote.example.net")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example.net")))
	if !request {
		m.AddAVP(diam.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success)))
	}
	if command == diam.CapabilitiesExchange {
		m.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))))
		m.AddAVP(diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(1)))
		m.AddAVP(diam.NewAVP(avp.ProductName, 0, 0, datatype.UTF8String("remote")))
		m.AddAVP(diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(contractApp)))
	}
	if command == diam.DisconnectPeer && request {
		m.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
	}
	return m
}
func contractDrop(m *diam.Message, code uint32) {
	for i, a := range m.AVP {
		if a.Code == code && a.VendorID == 0 {
			m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
			return
		}
	}
}
func contractField(t *testing.T, m *diam.Message, code uint32) *diam.AVP {
	t.Helper()
	a, err := m.FindAVP(code, 0)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func contractAccept(t *testing.T, frontend string, mandatory, validate, handshake bool, relay ...bool) *contractHarness {
	t.Helper()
	h := &contractHarness{dict: contractDict(t), events: make(chan diam.ProtocolErrorEvent, 8)}
	settings := contractSettings(h.dict, mandatory, validate)
	if len(relay) > 1 && relay[1] {
		settings.AuthApplicationID = nil
	}
	if len(relay) > 0 && relay[0] {
		settings.AuthApplicationID = append(settings.AuthApplicationID, diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0xffffffff)))
	}
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { h.events <- e }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &diam.Server{Dict: h.dict}
	if frontend == "sm" {
		admitted := make(chan diam.Conn, 1)
		settings.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { admitted <- c }
		state, err := sm.New(&settings)
		if err != nil {
			t.Fatal(err)
		}
		state.HandleFunc("ALL", func(c diam.Conn, m *diam.Message) {
			h.calls.Add(1)
			a := m.Answer(diam.CommandUnsupported)
			a.Header.CommandFlags |= diam.ErrorFlag
			a.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, settings.OriginHost))
			a.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm))
			_, _ = a.WriteTo(c)
		})
		srv.Handler = state
		h.disconnect = func() <-chan error {
			ch := make(chan error, 1)
			go func() { ch <- state.Disconnect(<-admitted, sm.DisconnectRebooting, time.Second) }()
			return ch
		}
	} else {
		manager, err := peer.New(peer.Config{Settings: settings, Timers: peer.Timers{TwInit: time.Hour}})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.AddPeer(peer.PeerConfig{Host: "remote.example.net", NoAutoReconnect: true}); err != nil {
			t.Fatal(err)
		}
		if err := manager.BindServer(srv); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.disconnect = func() <-chan error {
			ch := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				ch <- manager.Close(ctx, sm.DisconnectRebooting)
			}()
			return ch
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = manager.Close(ctx, sm.DisconnectRebooting)
		})
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	h.conn, err = net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.conn.Close() })
	if handshake {
		contractWrite(t, h.conn, contractBase(h.dict, diam.CapabilitiesExchange, true))
		if a := contractRead(t, h); contractCode(t, a) != diam.Success {
			t.Fatalf("handshake rejected: %v", a)
		}
	}
	return h
}

func contractReply(t *testing.T, h *contractHarness, request *diam.Message, result, failed uint32) {
	t.Helper()
	contractWrite(t, h.conn, request)
	answer := contractRead(t, h)
	if code := contractCode(t, answer); code != result {
		t.Fatalf("result=%d want=%d; answer=%v", code, result, answer)
	}
	if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || answer.Header.CommandFlags&diam.RequestFlag != 0 {
		t.Fatalf("answer lost request correlation: %+v", answer.Header)
	}
	groups := answer.FindAVPsWithPath(diam.AVPRef{Code: avp.FailedAVP})
	if failed != 0 {
		if len(groups) != 1 {
			t.Fatalf("Failed-AVP count=%d want 1", len(groups))
		}
		group, ok := groups[0].Data.(*diam.GroupedAVP)
		if !ok || len(group.AVP) != 1 || group.AVP[0].Code != failed {
			t.Fatalf("Failed-AVP evidence=%v want code=%d", groups[0], failed)
		}
	}
	event := contractEvent(t, h, request, result)
	contractBarrier(t, h, request, event.Closing)
	if h.calls.Load() != 0 {
		t.Fatal("rejected request reached application handler")
	}
}

// A response to the later DWR fences processing of the rejected request. An
// accidental continuation into Manager's unsupported-command path would put a
// second answer before this barrier, even though Manager has no handler counter.
func contractBarrier(t *testing.T, h *contractHarness, request *diam.Message, closing bool) {
	t.Helper()
	if closing {
		var b [1]byte
		if n, err := h.conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("rejected connection did not close without another answer: n=%d err=%v", n, err)
		}
	} else {
		barrier := contractBase(h.dict, diam.DeviceWatchdog, true)
		barrier.Header.HopByHopID = request.Header.HopByHopID ^ 0x80000000
		barrier.Header.EndToEndID = request.Header.EndToEndID ^ 0x40000000
		contractWrite(t, h.conn, barrier)
		next := contractRead(t, h)
		if next.Header.CommandCode != diam.DeviceWatchdog || next.Header.ApplicationID != 0 || next.Header.CommandFlags&diam.RequestFlag != 0 || next.Header.HopByHopID != barrier.Header.HopByHopID || next.Header.EndToEndID != barrier.Header.EndToEndID || contractCode(t, next) != diam.Success {
			t.Fatalf("unexpected response after rejection: got %+v, want barrier DWA hop=%#x end=%#x", next.Header, barrier.Header.HopByHopID, barrier.Header.EndToEndID)
		}
	}
	select {
	case extra := <-h.events:
		t.Fatalf("additional rejection notification after barrier: %+v", extra)
	default:
	}
}

// RFC 6733 §§3.2, 5.3.1, 5.4.1 and 5.5.1: base grammar is unconditional.
func TestBaseValidationRequestContract(t *testing.T) {
	commands := []struct {
		name     string
		code     uint32
		required []uint32
	}{
		{"CER", diam.CapabilitiesExchange, []uint32{avp.OriginHost, avp.OriginRealm, avp.HostIPAddress, avp.VendorID, avp.ProductName}},
		{"DWR", diam.DeviceWatchdog, []uint32{avp.OriginHost, avp.OriginRealm}},
		{"DPR", diam.DisconnectPeer, []uint32{avp.OriginHost, avp.OriginRealm, avp.DisconnectCause}},
	}
	for _, frontend := range []string{"sm", "manager"} {
		for _, validate := range []bool{false, true} {
			for _, command := range commands {
				for _, field := range command.required {
					for _, fault := range []string{"missing", "duplicate", "invalid length"} {
						if field == avp.HostIPAddress && fault == "duplicate" {
							continue
						} // 1* Host-IP-Address is repeatable.
						t.Run(fmt.Sprintf("%s/validate=%t/%s/%d/%s", frontend, validate, command.name, field, fault), func(t *testing.T) {
							h := contractAccept(t, frontend, false, validate, command.code != diam.CapabilitiesExchange)
							m := contractBase(h.dict, command.code, true)
							result := uint32(diam.MissingAVP)
							switch fault {
							case "missing":
								contractDrop(m, field)
							case "duplicate":
								a := *contractField(t, m, field)
								m.AddAVP(&a)
								result = diam.AVPOccursTooManyTimes
							case "invalid length":
								contractField(t, m, field).Data = datatype.Unknown{1}
								result = diam.InvalidAVPLength
							}
							// Identity and UTF8String permit one octet; use empty identity as the invalid-value vector.
							if fault == "invalid length" && (field == avp.OriginHost || field == avp.OriginRealm) {
								contractField(t, m, field).Data = datatype.DiameterIdentity("")
								result = diam.InvalidAVPValue
							}
							if fault == "invalid length" && field == avp.ProductName {
								contractField(t, m, field).Data = datatype.UTF8String(string([]byte{0xff}))
								result = diam.InvalidAVPValue
							}
							contractReply(t, h, m, result, field)
						})
					}
				}
				for _, fault := range []string{"application", "proxiable", "request error"} {
					t.Run(fmt.Sprintf("%s/validate=%t/%s/%s", frontend, validate, command.name, fault), func(t *testing.T) {
						h := contractAccept(t, frontend, false, validate, command.code != diam.CapabilitiesExchange)
						m := contractBase(h.dict, command.code, true)
						result := uint32(diam.InvalidHDRBits)
						switch fault {
						case "application":
							m.Header.ApplicationID = contractApp
						case "proxiable":
							m.Header.CommandFlags |= diam.ProxiableFlag
						case "request error":
							m.Header.CommandFlags |= diam.ErrorFlag
						}
						contractReply(t, h, m, result, 0)
					})
				}
			}
		}
	}
}

func contractRequest(d *dict.Parser) *diam.Message {
	m := diam.NewMessage(contractCommand, diam.RequestFlag|diam.ProxiableFlag, contractApp, 101, 202, d)
	m.AddAVP(diam.NewAVP(contractRequired, avp.Mbit, 0, datatype.Unsigned32(1)))
	return m
}

// RFC 6733 §§4.1 and 7.1.5, Verified Erratum 4615: one evidence container.
// The ordering (membership, mandatory AVPs, dictionary) is the shared contract.
func TestBaseValidationOptionalPipelineContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, mandatory := range []bool{false, true} {
			for _, validate := range []bool{false, true} {
				for _, fault := range []string{"valid", "unsupported malformed", "unknown", "vendor collision", "optional unknown", "nested unknown", "known optional group", "opaque optional group", "missing", "duplicate", "invalid flags", "nested missing"} {
					t.Run(fmt.Sprintf("%s/mandatory=%t/validate=%t/%s", frontend, mandatory, validate, fault), func(t *testing.T) {
						h := contractAccept(t, frontend, mandatory, validate, true)
						m := contractRequest(h.dict)
						result, failed := uint32(diam.CommandUnsupported), uint32(0)
						unknown := func(flags uint8, vendor uint32) *diam.AVP {
							return diam.NewAVP(contractUnknown, flags, vendor, datatype.Unknown{0, 0, 0, 1})
						}
						switch fault {
						case "unsupported malformed":
							m.Header.ApplicationID++
							contractDrop(m, contractRequired)
							m.AddAVP(unknown(avp.Mbit, 0))
							if validate || (!mandatory && frontend == "manager") {
								result = diam.ApplicationUnsupported
							} else if mandatory {
								result = diam.AVPUnsupported
								failed = contractUnknown
							}
						case "unknown":
							m.AddAVP(unknown(avp.Mbit, 0))
							if mandatory {
								result = diam.AVPUnsupported
								failed = contractUnknown
							}
						case "vendor collision":
							m.AddAVP(diam.NewAVP(contractRequired, avp.Vbit|avp.Mbit, 99999, datatype.Unknown{0, 0, 0, 1}))
							if mandatory {
								result = diam.AVPUnsupported
								failed = contractRequired
							}
						case "optional unknown":
							m.AddAVP(unknown(0, 0))
						case "nested unknown", "known optional group":
							m.AddAVP(diam.NewAVP(contractGroup, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(contractChild, avp.Mbit, 0, datatype.Unsigned32(1)), unknown(avp.Mbit, 0)}}))
							if fault == "known optional group" {
								contractField(t, m, contractGroup).Flags = 0
							}
							if mandatory {
								result = diam.AVPUnsupported
								failed = contractGroup
							}
						case "opaque optional group":
							m.AddAVP(diam.NewAVP(contractUnknown, 0, 0, &diam.GroupedAVP{AVP: []*diam.AVP{unknown(avp.Mbit, 0)}}))
						case "missing":
							contractDrop(m, contractRequired)
							if validate {
								result = diam.MissingAVP
								failed = contractRequired
							}
						case "duplicate":
							m.AddAVP(diam.NewAVP(contractRequired, avp.Mbit, 0, datatype.Unsigned32(2)))
							if validate {
								result = diam.AVPOccursTooManyTimes
								failed = contractRequired
							}
						case "invalid flags":
							contractField(t, m, contractRequired).Flags |= avp.Vbit
							if validate {
								result = diam.InvalidAVPBits
								failed = contractRequired
							}
						case "nested missing":
							m.AddAVP(diam.NewAVP(contractGroup, avp.Mbit, 0, &diam.GroupedAVP{}))
							if validate {
								result = diam.MissingAVP
								failed = contractGroup
							}
						}
						if result == diam.CommandUnsupported {
							contractWrite(t, h.conn, m)
							a := contractRead(t, h)
							if code := contractCode(t, a); code != result {
								t.Fatalf("result=%d want dispatch result=%d", code, result)
							}
							if frontend == "manager" {
								contractEvent(t, h, m, result)
							}
							contractBarrier(t, h, m, false)
							if frontend == "sm" && h.calls.Load() != 1 {
								t.Fatal("accepted request did not reach handler")
							}
						} else {
							contractReply(t, h, m, result, failed)
						}
					})
				}
			}
		}
	}
}

func contractDial(t *testing.T, frontend string) (*contractHarness, *diam.Message, <-chan error) {
	t.Helper()
	h := &contractHarness{dict: contractDict(t), events: make(chan diam.ProtocolErrorEvent, 8)}
	settings := contractSettings(h.dict, false, false)
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { h.events <- e }
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan error, 1)
	if frontend == "sm" {
		state, err := sm.New(&settings)
		if err != nil {
			t.Fatal(err)
		}
		client := &sm.Client{Dict: h.dict, Handler: state, MaxRetransmits: 0, RetransmitInterval: time.Second}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := client.DialContext(ctx, "tcp", l.Addr().String(), nil)
			if c != nil {
				t.Cleanup(c.Close)
			}
			done <- err
		}()
	} else {
		manager, err := peer.New(peer.Config{Settings: settings, Timers: peer.Timers{TwInit: time.Hour}, OnPeerEvent: func(e peer.PeerEvent) {
			if e.Peer.State == peer.IOpen {
				done <- nil
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.AddPeer(peer.PeerConfig{Host: "remote.example.net", NoAutoReconnect: true, Endpoints: []peer.Endpoint{{Network: "tcp", Address: l.Addr().String()}}}); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = manager.Close(ctx, sm.DisconnectRebooting)
		})
	}
	if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	h.conn, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.conn.Close() })
	return h, contractRead(t, h), done
}

// RFC 6733 §§3.2 and 5.3.2: CEA validation does not depend on ValidateRequests.
func TestBaseValidationCEAContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, field := range []uint32{avp.OriginHost, avp.OriginRealm, avp.ResultCode, avp.HostIPAddress, avp.VendorID, avp.ProductName} {
			for _, duplicate := range []bool{false, true} {
				if duplicate && field == avp.HostIPAddress {
					continue
				}
				t.Run(fmt.Sprintf("%s/%d/duplicate=%t", frontend, field, duplicate), func(t *testing.T) {
					h, cer, done := contractDial(t, frontend)
					cea := contractBase(h.dict, diam.CapabilitiesExchange, false)
					cea.Header.HopByHopID = cer.Header.HopByHopID
					cea.Header.EndToEndID = cer.Header.EndToEndID
					result := uint32(diam.MissingAVP)
					if duplicate {
						a := *contractField(t, cea, field)
						cea.AddAVP(&a)
						result = diam.AVPOccursTooManyTimes
					} else {
						contractDrop(cea, field)
					}
					contractWrite(t, h.conn, cea)
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("malformed CEA admitted the peer")
						}
					case e := <-h.events:
						if e.Err == nil || e.Err.ResultCode() != result {
							t.Fatalf("CEA rejection=%+v want result %d", e, result)
						}
					case <-time.After(time.Second):
						t.Fatal("malformed CEA neither rejected nor diagnosed")
					}
				})
			}
		}
	}
}

// RFC 6733 §§5.4.2 and 7.2: a generic E-bit DPA is valid without capability fields.
func TestBaseValidationErrorDPAContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h := contractAccept(t, frontend, false, false, true)
			done := h.disconnect()
			request := contractRead(t, h)
			if request.Header.CommandCode != diam.DisconnectPeer {
				t.Fatalf("wanted DPR, got %+v", request.Header)
			}
			answer := contractBase(h.dict, diam.DisconnectPeer, false)
			answer.Header.CommandFlags = diam.ErrorFlag | diam.ProxiableFlag
			answer.Header.HopByHopID = request.Header.HopByHopID
			answer.Header.EndToEndID = request.Header.EndToEndID
			contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(diam.TooBusy)
			contractWrite(t, h.conn, answer)
			e := contractEvent(t, h, answer, diam.TooBusy)
			if !errors.Is(e.Err, diam.ProtocolPeerRejected) || !e.Closing {
				t.Fatalf("valid E-bit DPA was not consumed as rejection: %+v", e)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("valid E-bit DPA did not complete disconnect")
			}
		})
	}
}

// RFC 6733 §§2.4 and 4.1: relay and redirect advertisements exempt unknown mandatory AVPs.
func TestBaseValidationRelayMandatoryContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h := contractAccept(t, frontend, true, true, true, true)
			m := contractRequest(h.dict)
			m.AddAVP(diam.NewAVP(contractUnknown, avp.Mbit, 0, datatype.Unknown{0, 0, 0, 1}))
			contractWrite(t, h.conn, m)
			if answer := contractRead(t, h); contractCode(t, answer) != diam.CommandUnsupported {
				t.Fatalf("relay rejected unknown mandatory AVP: %v", answer)
			}
			if frontend == "sm" && h.calls.Load() != 1 {
				t.Fatal("relay request did not reach handler")
			}
		})
	}
}

// RFC 6733 §§3 and 5.3.1: reserved header bits are ignored and addresses repeat.
func TestBaseValidationAcceptedGrammarContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, fault := range []string{"second address", "reserved bits"} {
			t.Run(frontend+"/"+fault, func(t *testing.T) {
				h := contractAccept(t, frontend, false, false, false)
				m := contractBase(h.dict, diam.CapabilitiesExchange, true)
				if fault == "second address" {
					m.AddAVP(diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.AddressFromIP(netip.MustParseAddr("::1"))))
				} else {
					m.Header.CommandFlags |= 0x0f
				}
				contractWrite(t, h.conn, m)
				if answer := contractRead(t, h); contractCode(t, answer) != diam.Success {
					t.Fatalf("valid base grammar rejected: %v", answer)
				}
			})
		}
	}
}

// RFC 6733 §§4.1 and 7.1.5: the setting also controls base-command unknowns.
func TestBaseValidationUnknownMandatoryContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, mode := range []string{"disabled", "enabled", "relay"} {
				for _, fault := range []string{"top", "nested", "vendor collision"} {
					t.Run(fmt.Sprintf("%s/%d/%s/%s", frontend, command, mode, fault), func(t *testing.T) {
						h := contractAccept(t, frontend, mode != "disabled", false, command != diam.CapabilitiesExchange, mode == "relay")
						m := contractBase(h.dict, command, true)
						failed := uint32(contractUnknown)
						unknown := diam.NewAVP(contractUnknown, avp.Mbit, 0, datatype.Unknown{0, 0, 0, 1})
						switch fault {
						case "top":
							m.AddAVP(unknown)
						case "nested":
							failed = avp.ProxyInfo
							m.AddAVP(diam.NewAVP(avp.ProxyInfo, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
								diam.NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example.net")),
								diam.NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("state")), unknown}}))
						case "vendor collision":
							failed = avp.OriginHost
							m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit|avp.Vbit, 99999, datatype.Unknown("remote.example.net")))
						}
						if mode == "enabled" {
							contractReply(t, h, m, diam.AVPUnsupported, failed)
						} else {
							contractWrite(t, h.conn, m)
							if answer := contractRead(t, h); contractCode(t, answer) != diam.Success {
								t.Fatalf("unknown mandatory exception rejected: %v", answer)
							}
						}
					})
				}
			}
		}
	}
}

// RFC 6733 §§5.3.2 and 7.2: E-bit CEA uses generic error-answer grammar.
func TestBaseValidationErrorCEAContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h, cer, _ := contractDial(t, frontend)
			cea := contractBase(h.dict, diam.DeviceWatchdog, false)
			cea.Header.CommandCode = diam.CapabilitiesExchange
			cea.Header.CommandFlags = diam.ErrorFlag | diam.ProxiableFlag
			cea.Header.HopByHopID = cer.Header.HopByHopID
			cea.Header.EndToEndID = cer.Header.EndToEndID
			contractField(t, cea, avp.ResultCode).Data = datatype.Unsigned32(diam.TooBusy)
			contractWrite(t, h.conn, cea)
			e := contractEvent(t, h, cea, diam.TooBusy)
			if !errors.Is(e.Err, diam.ProtocolCEARejected) || !e.Closing {
				t.Fatalf("generic error CEA was treated as malformed: %+v", e)
			}
		})
	}
}

// RFC 6733 §§5.4.2, 5.5.2 and 7: malformed answers are reported without
// answering them or consuming the pending disconnect.
func TestBaseValidationAnswerContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, field := range []uint32{avp.OriginHost, avp.OriginRealm, avp.ResultCode} {
				for _, fault := range []string{"missing", "duplicate", "invalid data"} {
					t.Run(fmt.Sprintf("%s/%d/%d/%s", frontend, command, field, fault), func(t *testing.T) {
						h := contractAccept(t, frontend, false, false, true)
						m := contractBase(h.dict, command, false)
						var done <-chan error
						if command == diam.DisconnectPeer {
							done = h.disconnect()
							request := contractRead(t, h)
							m.Header.HopByHopID, m.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
						}
						result := uint32(diam.MissingAVP)
						switch fault {
						case "missing":
							contractDrop(m, field)
						case "duplicate":
							a := *contractField(t, m, field)
							m.AddAVP(&a)
							result = diam.AVPOccursTooManyTimes
						case "invalid data":
							if field == avp.ResultCode {
								contractField(t, m, field).Data = datatype.Unknown{1}
								result = diam.InvalidAVPLength
							} else {
								contractField(t, m, field).Data = datatype.DiameterIdentity("")
								result = diam.InvalidAVPValue
							}
						}
						contractWrite(t, h.conn, m)
						e := contractEvent(t, h, m, result)
						if e.Reply != diam.ProtocolReplyNone || e.Closing {
							t.Fatalf("malformed answer changed transport or produced reply: %+v", e)
						}
						if done != nil {
							select {
							case err := <-done:
								t.Fatalf("malformed DPA completed disconnect: %v", err)
							default:
							}
							valid := contractBase(h.dict, command, false)
							valid.Header.HopByHopID, valid.Header.EndToEndID = m.Header.HopByHopID, m.Header.EndToEndID
							contractWrite(t, h.conn, valid)
							select {
							case <-done:
							case <-time.After(time.Second):
								t.Fatal("valid DPA did not finish disconnect")
							}
						} else {
							barrier := contractBase(h.dict, diam.DeviceWatchdog, true)
							barrier.Header.HopByHopID++
							contractWrite(t, h.conn, barrier)
							answer := contractRead(t, h)
							if answer.Header.HopByHopID != barrier.Header.HopByHopID || contractCode(t, answer) != diam.Success {
								t.Fatal("malformed DWA was answered or stopped subsequent traffic")
							}
						}
					})
				}
			}
		}
	}
}

func TestBaseValidationMembershipBeforeDecodeContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h := contractAccept(t, frontend, true, true, true)
			m := contractRequest(h.dict)
			m.Header.ApplicationID++
			contractField(t, m, contractRequired).Data = datatype.Unknown{1}
			m.AddAVP(diam.NewAVP(contractUnknown, avp.Mbit, 0, datatype.Unknown{1, 2, 3, 4}))
			contractReply(t, h, m, diam.ApplicationUnsupported, 0)
		})
	}
}

// RFC 6733 §7.1.3 requires E for protocol errors; success must never carry E.
func TestBaseValidationErrorBitContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, fault := range []string{"protocol without E", "success with E", "proxiable", "retransmitted", "application"} {
				t.Run(fmt.Sprintf("%s/%d/%s", frontend, command, fault), func(t *testing.T) {
					var h *contractHarness
					var request *diam.Message
					var disconnected <-chan error
					if command == diam.CapabilitiesExchange {
						h, request, _ = contractDial(t, frontend)
					} else {
						h = contractAccept(t, frontend, false, false, true)
						if command == diam.DisconnectPeer {
							disconnected = h.disconnect()
							request = contractRead(t, h)
						}
					}
					answer := contractBase(h.dict, command, false)
					if request != nil {
						answer.Header.HopByHopID, answer.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
					}
					switch fault {
					case "protocol without E":
						contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(diam.TooBusy)
					case "success with E":
						answer.Header.CommandFlags |= diam.ErrorFlag
					case "proxiable":
						answer.Header.CommandFlags |= diam.ProxiableFlag
					case "retransmitted":
						answer.Header.CommandFlags |= diam.RetransmittedFlag
					case "application":
						answer.Header.ApplicationID = contractApp
					}
					contractWrite(t, h.conn, answer)
					if fault == "application" && command == diam.DisconnectPeer {
						// Closing drops an unowned application answer before validation.
						select {
						case e := <-h.events:
							t.Fatalf("ineligible Closing answer reached validation: %+v", e)
						case <-time.After(20 * time.Millisecond):
						}
						valid := contractBase(h.dict, command, false)
						valid.Header.HopByHopID, valid.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
						contractWrite(t, h.conn, valid)
						select {
						case <-disconnected:
						case <-time.After(time.Second):
							t.Fatal("ineligible answer consumed pending disconnect")
						}
						return
					}
					result := uint32(diam.InvalidHDRBits)
					if fault == "application" && command == diam.CapabilitiesExchange {
						result = 0 // Wait-I-CEA accepts only base CEA, preserving part 1.
					}
					e := contractEvent(t, h, answer, result)
					if e.Reply != diam.ProtocolReplyNone {
						t.Fatal("answered malformed answer")
					}
				})
			}
		}
	}
}

// An application loaded after CER/CEA cannot retroactively extend that offer.
func TestBaseValidationApplicationSnapshotContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h := contractAccept(t, frontend, true, true, true, false, true)
			if err := h.dict.Load(strings.NewReader(strings.Replace(contractXML, `id="4242"`, `id="4244"`, 1))); err != nil {
				t.Fatal(err)
			}
			request := contractRequest(h.dict)
			request.Header.ApplicationID = 4244
			contractReply(t, h, request, diam.ApplicationUnsupported, 0)
		})
	}
}

func TestBaseValidationCEATypeContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, field := range []uint32{avp.OriginHost, avp.OriginRealm, avp.HostIPAddress, avp.VendorID, avp.ProductName, avp.ResultCode} {
			t.Run(fmt.Sprintf("%s/%d", frontend, field), func(t *testing.T) {
				h, cer, _ := contractDial(t, frontend)
				answer := contractBase(h.dict, diam.CapabilitiesExchange, false)
				answer.Header.HopByHopID, answer.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
				result := uint32(diam.InvalidAVPLength)
				switch field {
				case avp.OriginHost, avp.OriginRealm:
					contractField(t, answer, field).Data = datatype.DiameterIdentity("")
					result = diam.InvalidAVPValue
				case avp.ProductName:
					contractField(t, answer, field).Data = datatype.UTF8String(string([]byte{0xff}))
					result = diam.InvalidAVPValue
				default:
					contractField(t, answer, field).Data = datatype.Unknown{1}
				}
				contractWrite(t, h.conn, answer)
				e := contractEvent(t, h, answer, result)
				if e.Reply != diam.ProtocolReplyNone || !e.Closing {
					t.Fatalf("invalid CEA did not reject handshake without reply: %+v", e)
				}
			})
		}
	}
}

// RFC 6733 §§3, 3.2: cover every defined request-flag combination,
// with reserved bits clear and set; T remains legal only on requests.
func TestBaseValidationRequestFlagsContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for bits := uint8(0); bits < 8; bits++ {
				for _, reserved := range []uint8{0, 15} {
					t.Run(fmt.Sprintf("%s/%d/%d/%d", frontend, command, bits, reserved), func(t *testing.T) {
						h := contractAccept(t, frontend, false, false, command != diam.CapabilitiesExchange)
						m := contractBase(h.dict, command, true)
						m.Header.CommandFlags = diam.RequestFlag | bits<<4 | reserved
						if m.Header.CommandFlags&(diam.ProxiableFlag|diam.ErrorFlag) != 0 {
							contractReply(t, h, m, diam.InvalidHDRBits, 0)
							return
						}
						contractWrite(t, h.conn, m)
						if a := contractRead(t, h); contractCode(t, a) != diam.Success {
							t.Fatalf("valid request flags rejected: %v", a)
						}
					})
				}
			}
		}
	}
}

// RFC 6733 §4.1: understood M is independent of dictionary sending rules,
// and P/reserved bits are ignored; V with Vendor-Id zero is inconsistent.
func TestBaseValidationAVPFlagsContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for bits := uint8(0); bits < 8; bits++ {
			for _, reserved := range []uint8{0, 31} {
				t.Run(fmt.Sprintf("%s/%d/%d", frontend, bits, reserved), func(t *testing.T) {
					h := contractAccept(t, frontend, false, false, true)
					m := contractBase(h.dict, diam.DeviceWatchdog, true)
					contractField(t, m, avp.OriginHost).Flags = bits<<5 | reserved
					if bits&4 != 0 {
						contractReply(t, h, m, diam.InvalidAVPBits, avp.OriginHost)
						return
					}
					contractWrite(t, h.conn, m)
					if a := contractRead(t, h); contractCode(t, a) != diam.Success {
						t.Fatalf("understood AVP flags rejected: %v", a)
					}
				})
			}
		}
	}
}

func TestBaseValidationFatalRepeatedCERContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		t.Run(frontend, func(t *testing.T) {
			h := contractAccept(t, frontend, true, true, true)
			request := contractBase(h.dict, diam.CapabilitiesExchange, true)
			request.Header.Version = 2
			contractWrite(t, h.conn, request)
			e := contractEvent(t, h, request, diam.UnsupportedVersion)
			if !e.Closing {
				t.Fatalf("fatal repeated CER was treated as an ignored request: %+v", e)
			}
		})
	}
}
