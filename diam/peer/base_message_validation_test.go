package peer_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// RFC 6733 §§7.1.5, 7.2: a received permanent failure may use the generic
// error grammar, including for capability and disconnect answers.
func TestBaseValidationPermanentErrorContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DisconnectPeer} {
			for _, code := range []uint32{diam.AVPUnsupported, diam.UnableToComply, 5999} {
				for _, p := range []uint8{0, diam.ProxiableFlag} {
					t.Run(fmt.Sprintf("%s/%d/%d/P=%t", frontend, command, code, p != 0), func(t *testing.T) {
						var h *contractHarness
						var request *diam.Message
						var done <-chan error
						kind := diam.ProtocolCEARejected
						if command == diam.CapabilitiesExchange {
							h, request, _ = contractDial(t, frontend)
						} else {
							h = contractAccept(t, frontend, false, false, true)
							done = h.disconnect()
							request = contractRead(t, h)
							kind = diam.ProtocolPeerRejected
						}
						answer := contractBase(h.dict, diam.DeviceWatchdog, false)
						answer.Header.CommandCode = command
						answer.Header.CommandFlags = diam.ErrorFlag | p
						answer.Header.HopByHopID, answer.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
						contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(code)
						if code == diam.AVPUnsupported {
							// Verified Erratum 4615: a 5001 answer carries one Failed-AVP
							// holding the unsupported AVP.
							answer.AddAVP(diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(0xfffe, avp.Mbit, 0, datatype.OctetString("unsupported"))}}))
						}
						contractWrite(t, h.conn, answer)
						e := contractEvent(t, h, answer, code)
						if !errors.Is(e.Err, kind) || !e.Closing || e.Reply != diam.ProtocolReplyNone {
							t.Fatalf("permanent error lost its diagnosis or disposition: %+v", e)
						}
						if done != nil {
							select {
							case <-done:
							case <-time.After(time.Second):
								t.Fatal("E-bit permanent-error DPA did not complete disconnect")
							}
						}
					})
				}
			}
		}
	}
}

type baseValueFault struct {
	name   string
	field  uint32
	result uint32
	value  datatype.Type
	add    bool
}

func baseValueFaults() []baseValueFault {
	return []baseValueFault{
		{"destination host", avp.DestinationHost, diam.AVPNotAllowed, datatype.DiameterIdentity("destination.example.net"), true},
		{"destination realm", avp.DestinationRealm, diam.AVPNotAllowed, datatype.DiameterIdentity("example.net"), true},
		{"host high octet", avp.OriginHost, diam.InvalidAVPValue, datatype.DiameterIdentity("peer\xff.example"), false},
		{"realm high octet", avp.OriginRealm, diam.InvalidAVPValue, datatype.DiameterIdentity("realm\xff.example"), false},
		{"host NUL", avp.OriginHost, diam.InvalidAVPValue, datatype.DiameterIdentity("peer\x00.example"), false},
		{"realm NUL", avp.OriginRealm, diam.InvalidAVPValue, datatype.DiameterIdentity("realm\x00.example"), false},
		{"host empty label", avp.OriginHost, diam.InvalidAVPValue, datatype.DiameterIdentity("peer..example"), false},
		{"realm hyphen", avp.OriginRealm, diam.InvalidAVPValue, datatype.DiameterIdentity("-realm.example"), false},
		{"zero supported vendor", avp.SupportedVendorID, diam.InvalidAVPValue, datatype.Unsigned32(0), true},
	}
}

func (f baseValueFault) apply(t *testing.T, m *diam.Message) {
	t.Helper()
	if f.add {
		m.AddAVP(diam.NewAVP(f.field, avp.Mbit, 0, f.value))
	} else {
		contractField(t, m, f.field).Data = f.value
	}
}

func TestBaseValidationValuesRequestContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, fault := range baseValueFaults()[2:] {
				if fault.field == avp.SupportedVendorID && command != diam.CapabilitiesExchange {
					continue
				}
				t.Run(fmt.Sprintf("%s/%d/%s", frontend, command, fault.name), func(t *testing.T) {
					h := contractAccept(t, frontend, false, false, command != diam.CapabilitiesExchange)
					m := contractBase(h.dict, command, true)
					fault.apply(t, m)
					contractReply(t, h, m, fault.result, fault.field)
				})
			}
		}
	}
}

func TestBaseValidationValuesAnswerContract(t *testing.T) {
	for _, frontend := range []string{"sm", "manager"} {
		for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
			for _, flags := range []uint8{0, diam.ErrorFlag} {
				for _, fault := range baseValueFaults() {
					if fault.field == avp.SupportedVendorID && command != diam.CapabilitiesExchange {
						continue
					}
					t.Run(fmt.Sprintf("%s/%d/E=%t/%s", frontend, command, flags != 0, fault.name), func(t *testing.T) {
						var h *contractHarness
						var request *diam.Message
						var done <-chan error
						kind := diam.ProtocolInvalidDWA
						if command == diam.CapabilitiesExchange {
							h, request, _ = contractDial(t, frontend)
							kind = diam.ProtocolCEARejected
						} else {
							h = contractAccept(t, frontend, false, false, true)
							if command == diam.DisconnectPeer {
								done = h.disconnect()
								request = contractRead(t, h)
								kind = diam.ProtocolInvalidDPA
							}
						}
						answer := contractBase(h.dict, command, false)
						answer.Header.CommandFlags = flags
						if flags != 0 {
							contractField(t, answer, avp.ResultCode).Data = datatype.Unsigned32(diam.TooBusy)
						}
						if request != nil {
							answer.Header.HopByHopID, answer.Header.EndToEndID = request.Header.HopByHopID, request.Header.EndToEndID
						}
						fault.apply(t, answer)
						contractWrite(t, h.conn, answer)
						e := contractEvent(t, h, answer, fault.result)
						if e.Err.Kind() != kind || e.Reply != diam.ProtocolReplyNone || e.Closing != (command == diam.CapabilitiesExchange) {
							t.Fatalf("malformed answer disposition: %+v", e)
						}
						if done != nil {
							select {
							case err := <-done:
								t.Fatalf("malformed DPA completed disconnect: %v", err)
							default:
							}
							valid := contractBase(h.dict, command, false)
							valid.Header.HopByHopID, valid.Header.EndToEndID = answer.Header.HopByHopID, answer.Header.EndToEndID
							contractWrite(t, h.conn, valid)
							select {
							case <-done:
							case <-time.After(time.Second):
								t.Fatal("valid replacement DPA did not complete disconnect")
							}
						} else if command == diam.DeviceWatchdog {
							barrier := contractBase(h.dict, diam.DeviceWatchdog, true)
							barrier.Header.HopByHopID++
							contractWrite(t, h.conn, barrier)
							got := contractRead(t, h)
							if got.Header.CommandCode != barrier.Header.CommandCode || got.Header.HopByHopID != barrier.Header.HopByHopID || got.Header.EndToEndID != barrier.Header.EndToEndID || contractCode(t, got) != diam.Success {
								t.Fatalf("malformed DWA was answered or blocked barrier: %+v", got.Header)
							}
						}
					})
				}
			}
		}
	}
}
