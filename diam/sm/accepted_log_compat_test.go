package sm

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// RFC 6733 §§5.4,5.5,6.3: these discarded controls retain the existing
// StateMachine log cause and observer result, including a modified hook body.
func TestAcceptedInvalidControlLogCompatibilityWire(t *testing.T) {
	for _, variant := range []string{"DWR-bound-host", "DPR-bound-host", "DWR-post-hook-missing-host"} {
		t.Run(variant, func(t *testing.T) {
			var mutated atomic.Bool
			p := newProtocolWire(t, func(cfg *Settings) {
				if variant == "DWR-post-hook-missing-host" {
					cfg.OnDWR = func(_ diam.Conn, m *diam.Message) {
						if mutated.Swap(true) {
							return
						}
						for i, a := range m.AVP {
							if a.Code == avp.OriginHost {
								m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
								return
							}
						}
					}
				}
			}, true)
			m := regressionDWR(t)
			kind, text := diam.ProtocolInvalidDWR, "sm: invalid DWR"
			wantCause := "DWR Origin-Host does not match the admitted peer (RFC 6733 §6.3)"
			switch variant {
			case "DPR-bound-host":
				m = closingContractDPR(t, p, 0x9ca0)
				kind, text = diam.ProtocolInvalidDPR, "sm: invalid DPR"
				wantCause = "DPR Origin-Host does not match the admitted peer (RFC 6733 §6.3)"
			case "DWR-post-hook-missing-host":
				wantCause = smparser.ErrMissingOriginHost.Error()
			}
			if variant != "DWR-post-hook-missing-host" {
				setWireIdentity(t, m, avp.OriginHost, "wrong.example")
			}
			header := p.send(t, m)
			e := protocolEvent(t, p.events)
			assertProtocolEvent(t, e, p.conn, &header, kind, 0, false, diam.ProtocolReplyNone, 0)
			records := p.logs.Records()
			if len(records) != 1 || records[0].Message != text || records[0].Level != slog.LevelWarn {
				t.Fatalf("invalid control logs=%v want WARN %q", records, text)
			}
			cause, ok := logtest.Attr(records[0], "error").Any().(error)
			if !ok || cause == nil || cause.Error() != wantCause {
				t.Fatalf("log cause=%v (%T), want %q", cause, cause, wantCause)
			}
			if variant == "DWR-post-hook-missing-host" && (!mutated.Load() || !errors.Is(cause, smparser.ErrMissingOriginHost)) {
				t.Fatalf("post-hook parser cause lost identity: %v (%T)", cause, cause)
			}
			p.usable(t)
		})
	}
}
