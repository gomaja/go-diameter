package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func admissionMetadata(shape string) *smpeer.Metadata {
	if shape == "absent" {
		return nil
	}
	peer := &smpeer.Metadata{OriginHost: "saved.example", OriginRealm: "example", Applications: []uint32{1001}}
	if shape == "CER" || shape == "both" {
		peer.CER = &smparser.CER{}
	}
	if shape == "CEA" || shape == "both" {
		peer.CEA = &smparser.CEA{}
	}
	return peer
}

func replaceAdmission(c diam.Conn, shape string) {
	c.SetContext(smpeer.NewContext(c.Context(), admissionMetadata(shape)))
}

// The disposition selected on receipt survives changes made by the CER hook.
// Context changes remain authoritative only until genuine CER admission starts.
func TestAdmissionRefreshPreservesCERDisposition(t *testing.T) {
	shapes := []string{"CER", "bare", "CEA", "both", "absent"}
	for _, initial := range shapes {
		for _, replacement := range shapes {
			for _, when := range []string{"before", "during", "after"} {
				if when == "during" && (initial == "CER" || initial == "bare") {
					continue
				}
				t.Run(initial+"/"+replacement+"/"+when, func(t *testing.T) {
					c := newHandshakeConn()
					replaceAdmission(c, initial)
					cfg := testMessageErrorSettings(c.Dictionary())
					cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
					cfg.HostIPAddresses = []datatype.Address{localhostAddress}
					var cerCalls, ceaCalls, handshakes, notices int
					cfg.OnCER = func(c diam.Conn, _ *diam.Message) {
						cerCalls++
						if when == "during" {
							replaceAdmission(c, replacement)
						}
					}
					cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaCalls++ }
					cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes++ }
					cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
						notices++
						if e.Err.Kind() != diam.ProtocolUnexpectedMessage {
							t.Errorf("unexpected notice: %+v", e)
						}
					}
					sm := mustNewStateMachine(t, cfg, c.Dictionary())
					m := regressionCER(t, c.Dictionary(), 1001)
					state := sm.acceptedCore(c, m, true)
					if when == "before" {
						replaceAdmission(c, replacement)
					}
					sm.ServeDIAM(c, m)
					if when == "after" {
						replaceAdmission(c, replacement)
					}
					// An unknown continuation refreshes claims without selecting another
					// receive disposition or generating protocol traffic.
					state.run(state.prepare(protocol.Input{Kind: protocol.Continue}))
					genuine := initial == "absent" || when == "before" && replacement == "absent"
					selected := initial
					if when == "before" && initial != "absent" {
						selected = replacement
					}
					wantCER, wantCEA, wantHandshake, wantNotice, wantWrites := 0, 0, 0, 0, 0
					if genuine {
						wantCER, wantCEA, wantHandshake, wantWrites = 1, 1, 1, 1
					} else if selected == "CEA" || selected == "both" {
						wantCER, wantNotice = 1, 1
					}
					if cerCalls != wantCER || ceaCalls != wantCEA || handshakes != wantHandshake || notices != wantNotice || len(c.writes) != wantWrites {
						t.Fatalf("CER/CEA/handshake/notices/writes=%d/%d/%d/%d/%d, want %d/%d/%d/%d/%d", cerCalls, ceaCalls, handshakes, notices, len(c.writes), wantCER, wantCEA, wantHandshake, wantNotice, wantWrites)
					}
					if genuine {
						if state.passiveResponder() || state.snapshot().Capabilities().Host == "saved.example" {
							t.Fatal("genuine admission retained external ownership")
						}
					} else if !state.passiveResponder() {
						t.Fatal("repeated CER surrendered external ownership")
					}
					// Fixture has no lifecycle channel and therefore no accept deadline.
					c.Close()
					state.apply(protocol.Input{Kind: protocol.TransportLost, At: time.Now()})
				})
			}
		}
	}
}
