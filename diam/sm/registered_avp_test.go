package sm

import (
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

// TestRegisteredAVPsAdvertiseNoApplication: capability exchange advertises
// the applications the dictionaries declare (RFC 6733 §5.3), and
// registering AVPs for an application declares none.
func TestRegisteredAVPsAdvertiseNoApplication(t *testing.T) {
	p := dict.New(dict.Base, dict.Gx)
	before := PrepareSupportedApps(p)
	for _, app := range []uint32{4, 16777999} {
		if err := p.RegisterAVP(app, &dict.AVP{Name: "Registered-Test", Code: 70000, VendorID: 99999,
			Must: "V", Data: dict.Data{TypeName: "UTF8String"}}); err != nil {
			t.Fatal(err)
		}
	}
	after := PrepareSupportedApps(p)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("supported applications changed from %v to %v", before, after)
	}
	if len(after) != 2 || after[0].ID != 3 || after[1].ID != 16777238 {
		t.Fatalf("supported applications = %v, want 3 and 16777238", after)
	}
}
