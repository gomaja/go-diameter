package dict

import "testing"

func TestApplicationAuthorVendor(t *testing.T) {
	for _, tc := range []struct{ id, want uint32 }{
		{0, 0}, {4, 0}, {16777215, 0}, {16777216, 10415}, {4294967294, 10415}, {4294967295, 0},
	} {
		app := &App{ID: tc.id, Vendor: []*Vendor{{ID: 10415}, {ID: 13019}, {ID: 5535}}}
		if got := app.ApplicationVendor(); got != tc.want {
			t.Errorf("app %d author=%d, want %d", tc.id, got, tc.want)
		}
	}
	for _, app := range Default.Apps() {
		if IsVendorSpecificApplication(app.ID) && app.ApplicationVendor() != 10415 {
			t.Errorf("bundled 3GPP app %d author=%d, want 10415", app.ID, app.ApplicationVendor())
		}
	}
}
