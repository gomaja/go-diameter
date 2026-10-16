package peer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
)

// Complete frames with an AVP overrunning their body retain recognizable
// headers and the next message boundary. Decode and transmit the same bytes.
func malformedCEAWire(t *testing.T, m *Manager, h diam.Header, fatal bool) []byte {
	t.Helper()
	h.MessageLength = diam.HeaderLength + 8
	if fatal {
		h.MessageLength = diam.HeaderLength - 1
	}
	raw := h.Serialize()
	if !fatal {
		raw = append(raw, make([]byte, 8)...)
		binary.BigEndian.PutUint32(raw[20:24], avp.ResultCode)
		raw[24] = avp.Mbit
		raw[27] = 12 // Eight header octets plus four absent value octets.
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(raw), m.dictionary())
	var me *diam.MessageError
	if !errors.As(err, &me) || me.Fatal != fatal || decoded == nil || decoded.Header == nil || *decoded.Header != h {
		t.Fatalf("raw fixture did not reach intended decoder path: message=%v error=%T(%v) fatal=%t", decoded, err, err, fatal)
	}
	result := uint32(diam.InvalidAVPLength)
	if fatal {
		result = diam.InvalidMessageLength
	} else if int(h.MessageLength) != len(raw) {
		t.Fatal("nonfatal fixture must contain a complete frame")
	}
	if me.ResultCode != result {
		t.Fatalf("decoder Result-Code=%d want%d", me.ResultCode, result)
	}
	t.Logf("decoded recognizable header: cmd=%d app=%d flags=%#x Hop=%d End=%d Fatal=%t Result-Code=%d", h.CommandCode, h.ApplicationID, h.CommandFlags, h.HopByHopID, h.EndToEndID, me.Fatal, me.ResultCode)
	return raw
}

func writeMalformedCEA(t *testing.T, c net.Conn, raw []byte) {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("raw write=%d/%d error=%v", n, len(raw), err)
	}
}

// RFC 6733 §§3, 5.3, 6.2.1: body decode errors cannot give an unrelated
// answer ownership of this connection generation's outstanding CER.
func TestManagerMalformedCEACorrelationOnWire(t *testing.T) {
	for _, field := range []string{"hop", "end"} {
		for _, finish := range []string{"good followup", "original deadline"} {
			t.Run(field+"/"+finish, func(t *testing.T) {
				clock := &fakeClock{}
				m, c, cer, events := correlationDial(t, clock)
				h := *cer.Header
				h.CommandFlags = 0
				if field == "hop" {
					h.HopByHopID++
				} else {
					h.EndToEndID++
				}
				raw := malformedCEAWire(t, m, h, false)
				mark := clock.timerCount()
				for range 2 {
					writeMalformedCEA(t, c, raw)
					e := correlationEvent(t, events, diam.ProtocolUnexpectedMessage, false)
					if e.Err.ResultCode() != 0 {
						t.Fatalf("stray CEA interpreted malformed body: %v", e.Err)
					}
					if p := m.Peers()[0]; p.State != WaitICEA || p.Eligible || p.Realm != "" {
						t.Fatalf("stray malformed CEA consumed admission: %+v", p)
					}
					if clock.timerCount() != mark {
						t.Fatal("stray malformed CEA replaced original deadline")
					}
				}
				if finish == "original deadline" {
					clock.fire()
					correlationEvent(t, events, diam.ProtocolHandshakeTimeout, true)
					correlationEOF(t, c)
					awaitState(t, m, Closed)
					return
				}
				write(t, c, correlationCEA(t, cer, "known.example.net"))
				awaitState(t, m, IOpen)
				if p := m.Peers()[0]; !p.Eligible || p.Realm != "example.net" {
					t.Fatalf("valid followup not admitted: %+v", p)
				}
				write(t, c, watchdogRequest(t))
				if answer := read(t, c); answer.Header.CommandCode != diam.DeviceWatchdog || code(t, answer) != diam.Success {
					t.Fatalf("valid followup connection unusable: %v", answer)
				}
			})
		}
	}
}

func TestManagerMalformedCEARejectionControlsOnWire(t *testing.T) {
	for _, scenario := range []string{"correlated", "fatal stray", "fatal correlated", "wrong command", "wrong application", "request direction"} {
		t.Run(scenario, func(t *testing.T) {
			m, c, cer, events := correlationDial(t, &fakeClock{})
			h := *cer.Header
			h.CommandFlags = 0
			if scenario != "correlated" && scenario != "fatal correlated" {
				h.HopByHopID++
			}
			fatal := scenario == "fatal stray" || scenario == "fatal correlated"
			switch scenario {
			case "wrong command":
				h.CommandCode = diam.DeviceWatchdog
			case "wrong application":
				h.ApplicationID = 4
			case "request direction":
				h.CommandFlags = diam.RequestFlag
			}
			writeMalformedCEA(t, c, malformedCEAWire(t, m, h, fatal))
			e := correlationEvent(t, events, diam.ProtocolHandshakeState, true)
			result := uint32(diam.InvalidAVPLength)
			if fatal {
				result = diam.InvalidMessageLength
			}
			if e.Err.ResultCode() != result {
				t.Fatalf("malformed rejection result=%d want%d", e.Err.ResultCode(), result)
			}
			correlationEOF(t, c)
			awaitState(t, m, Closed)
		})
	}
}
