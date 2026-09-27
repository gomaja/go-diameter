package dict

import "testing"

func TestSMSApplicationsAndCommands(t *testing.T) {
	// 3GPP TS 29.338 V19.3.0 §§4.1, 5.3.2.2, 6.3.2.2; Tables 5.3.2.2/1, 6.3.2.2/1.
	for _, tc := range []struct {
		app uint32
		commands []uint32
	}{
		{16777312, []uint32{8388647, 8388648, 8388649}},
	} {
		if _, err := Default.App(tc.app); err != nil {
			t.Errorf("application %d: %v", tc.app, err)
		}
		for _, code := range tc.commands {
			if _, err := Default.FindCommand(tc.app, code); err != nil {
				t.Errorf("application %d command %d: %v", tc.app, code, err)
			}
		}
	}
}
