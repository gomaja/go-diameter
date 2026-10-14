package dict_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

// 3GPP TS 29.229 V19.1.0 §6.1 and TS 29.329 V19.1.0 §6.1.
func TestCxShApplicationsAndCommands(t *testing.T) {
	reference := newAllTestParser(t)

	for _, tc := range []struct {
		app         uint32
		first, last uint32
	}{
		{16777216, 300, 305},
		{16777217, 306, 309},
	} {
		app, err := reference.App(tc.app)
		if err != nil {
			t.Errorf("application %d: %v", tc.app, err)
			continue
		}
		if len(app.Command) != int(tc.last-tc.first+1) {
			t.Errorf("application %d: %d commands", tc.app, len(app.Command))
		}
		for code := tc.first; code <= tc.last; code++ {
			cmd, err := reference.FindCommand(tc.app, code)
			if err != nil {
				t.Error(err)
				continue
			}
			for _, side := range []dict.CommandRule{cmd.Request, cmd.Answer} {
				if side.Proxiable == nil || !*side.Proxiable {
					t.Errorf("%d/%d: PXY required", tc.app, code)
				}
			}
		}
	}
}
