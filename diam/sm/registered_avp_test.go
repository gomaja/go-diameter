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
	p := dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.Gx)
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
	ids := make([]uint32, len(after))
	for i, app := range after {
		ids[i] = app.ID
	}
	if !reflect.DeepEqual(ids, []uint32{3, 4, 16777238, 1, 4}) {
		t.Fatalf("supported application IDs = %v, want [3 4 16777238 1 4]", ids)
	}
}
