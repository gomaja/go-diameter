package main

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// TestS6aRequestsCarryRAndPAndValidate guards the AIR and ULR this client
// sends: their headers are "REQ, PXY" (3GPP TS 29.272 V19.6.0 §§7.2.3,
// 7.2.5), and each must pass Message.Validate, which checks the P bit
// against the dictionary.
func TestS6aRequestsCarryRAndPAndValidate(t *testing.T) {
	cfg := &sm.Settings{OriginHost: "mme.example.org", OriginRealm: "example.org"}
	meta := &smpeer.Metadata{OriginHost: "hss.example.org", OriginRealm: "example.org"}
	for _, tc := range []struct {
		name  string
		build func(*sm.Settings, *smpeer.Metadata) (*diam.Message, error)
	}{
		{"AIR", newAIR},
		{"ULR", newULR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := tc.build(cfg, meta)
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
