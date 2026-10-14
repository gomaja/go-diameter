package dict_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

func TestApplicationAuthorVendor(t *testing.T) {
	reference := newAllTestParser(t)

	for _, tc := range []struct{ id, want uint32 }{
		{0, 0}, {4, 0}, {16777215, 0}, {16777216, 10415}, {4294967294, 10415}, {4294967295, 0},
	} {
		app := &dict.App{ID: tc.id, Vendor: []*dict.Vendor{{ID: 10415}, {ID: 13019}, {ID: 5535}}}
		if got := app.ApplicationVendor(); got != tc.want {
			t.Errorf("app %d author=%d, want %d", tc.id, got, tc.want)
		}
	}
	for _, app := range reference.Apps() {
		if dict.IsVendorSpecificApplication(app.ID) && app.ApplicationVendor() != 10415 {
			t.Errorf("bundled 3GPP app %d author=%d, want 10415", app.ID, app.ApplicationVendor())
		}
	}
}
