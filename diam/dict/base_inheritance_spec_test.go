package dict

import (
	"fmt"
	"testing"
)

// RFC 6733 §4.5 and the companion sources in base_spec.json govern every
// inherited base definition. Local 3GPP overrides remain application-scoped.
func TestBaseDefinitionsAcrossApplications(t *testing.T) {
	overrides := map[uint32]map[string]uint32{
		16777216: {"DRMP": 16777216, "OC-Supported-Features": 16777216, "OC-OLR": 16777216, "Load": 16777216},
		16777217: {"DRMP": 16777216, "OC-Supported-Features": 16777216, "OC-OLR": 16777217, "Load": 16777216},
		16777236: {"Load": 16777236}, 16777238: {"Load": 16777238},
		16777251: {"DRMP": 16777251, "OC-Supported-Features": 16777251, "OC-OLR": 16777251, "Load": 16777251},
		16777252: {"DRMP": 16777252},
		16777265: {"DRMP": 16777251, "OC-Supported-Features": 16777251, "OC-OLR": 16777251, "Load": 16777251},
		16777302: {"Load": 16777302},
		16777312: {"DRMP": 16777312},
		16777313: {"DRMP": 16777312},
	}
	seen := map[uint32]bool{}
	for _, app := range Default.Apps() {
		if seen[app.ID] {
			continue
		}
		seen[app.ID] = true
		t.Run(fmt.Sprint(app.ID), func(t *testing.T) {
			for _, want := range loadBaseSpec(t).AVPs {
				got, err := Default.FindAVP(app.ID, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				owner := overrides[app.ID][want.Name]
				if got.App.ID != owner {
					t.Errorf("%s owner=%d, want %d", want.Name, got.App.ID, owner)
				}
				if owner != 0 {
					continue
				}
				rxCheckAVP(t, got, want)
				source, err := Default.FindAVP(0, want.Code, want.Vendor)
				if err != nil {
					t.Fatal(err)
				}
				if got != source {
					t.Errorf("%s must inherit the identical base definition", want.Name)
				}
			}
		})
	}
	if len(seen) != 14 {
		t.Fatalf("covered %d applications, want 14", len(seen))
	}
}
