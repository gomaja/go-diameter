package sm

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// A completed CER exchange decides the disposition of decoded base CEAs before
// body/header semantics; matching late CEAs stay silent and stray ones warn.
func TestClientCompletedCEADispositionTCP(t *testing.T) {
	for _, correlation := range []string{"matched", "hop", "end"} {
		for _, body := range []string{"valid", "missing-avps", "failed-result", "invalid-flags", "invalid-identity"} {
			t.Run(correlation+"/"+body, func(t *testing.T) {
				var handshakes, cerHooks atomic.Int32
				p := newClientCoreTCP(t, func(c *Client) {
					c.Handler.cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
					c.Handler.cfg.OnCER = func(diam.Conn, *diam.Message) { cerHooks.Add(1) }
				})
				admitClientCoreTCP(t, p)
				answer := protocolClientCEA(p.cer, diam.Success)
				switch body {
				case "missing-avps":
					answer.AVP = nil
				case "failed-result":
					answer = protocolClientCEA(p.cer, diam.NoCommonApplication)
				case "invalid-flags":
					answer.Header.CommandFlags |= diam.RetransmittedFlag
				case "invalid-identity":
					for _, a := range answer.AVP {
						if a.Code == avp.OriginHost {
							a.Data = datatype.DiameterIdentity("")
						}
					}
				}
				switch correlation {
				case "hop":
					answer.Header.HopByHopID++
				case "end":
					answer.Header.EndToEndID++
				}
				header := p.send(t, answer)
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
				records := p.logs.Records()
				if correlation == "matched" {
					if len(records) != 0 {
						t.Fatalf("completed matching CEA produced warning: %+v", records)
					}
				} else {
					assertDiscardWarning(t, records, "CEA", "identifiers mismatch")
				}
				// This response proves the production reader/dispatcher continued
				// after observing the CEA, rather than the fixture returning early.
				request := regressionDWR(t)
				setWireIdentity(t, request, avp.OriginHost, "peer.example")
				setWireIdentity(t, request, avp.OriginRealm, "example")
				dwrHeader := p.send(t, request)
				dwa, err := diam.ReadMessage(p.peer, p.client.Dict)
				if err != nil || dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.HopByHopID != dwrHeader.HopByHopID || !testResultCode(dwa, diam.Success) || p.conn.Closed() {
					t.Fatalf("CEA changed admitted connection: answer=%v err=%v", dwa, err)
				}
				if handshakes.Load() != 1 || cerHooks.Load() != 0 {
					t.Fatalf("CEA reached hook/callback: handshake=%d CER=%d", handshakes.Load(), cerHooks.Load())
				}
				p.noExtraEvents(t)
			})
		}
	}
}

// Decoding failures and non-base application headers retain their separate
// diagnostics; the completed-CEA shortcut applies to decoded base answers.
func TestClientCompletedCEAErrorBoundariesTCP(t *testing.T) {
	for _, fault := range []string{"application", "decode", "fatal"} {
		t.Run(fault, func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			admitClientCoreTCP(t, p)
			kind, code, closing := diam.ProtocolInvalidHeader, uint32(diam.InvalidHDRBits), false
			var header diam.Header
			if fault == "application" {
				answer := protocolClientCEA(p.cer, diam.Success)
				answer.Header.ApplicationID = 4
				header = p.send(t, answer)
			} else {
				var wire []byte
				header, wire = malformedCEAWire(t, p, fault)
				writeSMErrorWire(t, p.peer, wire)
				kind, code = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
				if fault == "fatal" {
					code, closing = diam.UnsupportedVersion, true
				}
			}
			assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &header, kind, code, closing, diam.ProtocolReplyNone, 0)
			for _, record := range p.logs.Records() {
				if strings.Contains(record.Message, "CEA rejected") {
					t.Fatalf("completed CEA error used handshake rejection log: %s", record.Message)
				}
			}
			if closing {
				p.closed(t)
			} else {
				request := regressionDWR(t)
				setWireIdentity(t, request, avp.OriginHost, "peer.example")
				setWireIdentity(t, request, avp.OriginRealm, "example")
				h := p.send(t, request)
				answer, err := diam.ReadMessage(p.peer, p.client.Dict)
				if err != nil || answer.Header.CommandCode != diam.DeviceWatchdog || answer.Header.HopByHopID != h.HopByHopID || p.conn.Closed() {
					t.Fatalf("nonfatal late CEA disturbed connection: answer=%v err=%v", answer, err)
				}
			}
			p.noExtraEvents(t)
		})
	}
}

func TestClientCompletedCEAClosingTCP(t *testing.T) {
	p := newClientCoreTCP(t, nil)
	admitClientCoreTCP(t, p)
	disconnected := make(chan error, 1)
	go func() { disconnected <- p.client.Handler.Disconnect(p.conn, DisconnectRebooting, time.Hour) }()
	dpr, err := diam.ReadMessage(p.peer, p.client.Dict)
	if err != nil || dpr.Header.CommandCode != diam.DisconnectPeer || dpr.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("Disconnect request=%v error=%v", dpr, err)
	}
	for _, shape := range []string{"valid", "missing", "flags"} {
		cea := protocolClientCEA(p.cer, diam.Success)
		switch shape {
		case "missing":
			cea.AVP = nil
		case "flags":
			cea.Header.CommandFlags |= diam.RetransmittedFlag
		}
		p.send(t, cea)
	}
	// A stray DPA provides a production dispatch barrier after all three CEAs.
	dpa := dpr.Answer(diam.Success)
	dpa.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	dpa.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	dpa.Header.EndToEndID++
	h := p.send(t, dpa)
	assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, &h, diam.ProtocolUnexpectedMessage, 0, false, diam.ProtocolReplyNone, 0)
	for _, record := range p.logs.Records() {
		if strings.Contains(record.Message, "CEA") {
			t.Fatalf("Closing CEA generated log: %s", record.Message)
		}
	}
	dpa.Header.EndToEndID--
	p.send(t, dpa)
	select {
	case err := <-disconnected:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("late CEA prevented Disconnect completion")
	}
	p.closed(t)
	p.noExtraEvents(t)
}
