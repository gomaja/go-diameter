package sm

import (
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/gx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"

	"github.com/gomaja/go-diameter/diam/dict"
)

// TestRegisteredAVPsAdvertiseNoApplication: capability exchange advertises
// the applications the dictionaries declare (RFC 6733 §5.3), and
// registering AVPs for an application declares none.
func TestRegisteredAVPsAdvertiseNoApplication(t *testing.T) {
	p := newTestDictionary(dict.Base(), nasreq.Dictionary(), creditcontrol.Dictionary(), rorf.Dictionary(), gx.Dictionary())
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
	if !reflect.DeepEqual(ids, []uint32{3, 4, 16777238, 1, 4, 3}) {
		t.Fatalf("supported application IDs = %v, want [3 4 16777238 1 4 3]", ids)
	}
}
