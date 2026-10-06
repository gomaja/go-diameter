package service

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
	"github.com/gomaja/go-diameter/examples/s6a_proxy/protos"
)

// TestS6aRequestsCarryRAndPAndValidate guards the AIR and ULR the proxy
// sends: their headers are "REQ, PXY" (3GPP TS 29.272 V19.6.0 §§7.2.3,
// 7.2.5), and each must pass Message.Validate, which checks the P bit
// against the dictionary.
func TestS6aRequestsCarryRAndPAndValidate(t *testing.T) {
	cfg := (&S6aProxyConfig{}).CloneWithDefaults()
	meta := &smpeer.Metadata{OriginHost: "hss.example.org", OriginRealm: "example.org"}
	plmn := []byte{0x00, 0xf1, 0x10}
	for _, tc := range []struct {
		name  string
		build func() (*diam.Message, error)
	}{
		{"AIR", func() (*diam.Message, error) {
			return newAIR(cfg, meta, genSID(), &protos.AuthenticationInformationRequest{
				UserName:                   "001010000000001",
				VisitedPlmn:                plmn,
				NumRequestedEutranVectors:  3,
				ImmediateResponsePreferred: true,
				ResyncInfo:                 make([]byte, 30),
			})
		}},
		{"ULR", func() (*diam.Message, error) {
			return newULR(cfg, meta, genSID(), &protos.UpdateLocationRequest{
				UserName:    "001010000000001",
				VisitedPlmn: plmn,
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := tc.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if got, want := m.Header.CommandFlags, uint8(diam.RequestFlag|diam.ProxiableFlag); got != want {
				t.Fatalf("command flags = %#x, want %#x (R and P)", got, want)
			}
			if err := m.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}
