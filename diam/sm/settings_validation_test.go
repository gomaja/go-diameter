package sm

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestSettingsValidateHostIPAddresses(t *testing.T) {
	valid := datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))
	for _, tc := range []struct {
		name     string
		settings *Settings
		wantErr  string
	}{
		{name: "nil settings", wantErr: "nil settings"},
		{name: "empty settings", settings: &Settings{}},
		{name: "valid address", settings: &Settings{HostIPAddresses: []datatype.Address{valid}}},
		{name: "other family", settings: &Settings{HostIPAddresses: []datatype.Address{{Family: datatype.AddressFamilyE164, Value: []byte("123")}}}},
		{name: "invalid family", settings: &Settings{HostIPAddresses: []datatype.Address{{Family: 0}}}, wantErr: "HostIPAddresses[0]"},
		{name: "reserved family", settings: &Settings{HostIPAddresses: []datatype.Address{{Family: 65535}}}, wantErr: "HostIPAddresses[0]"},
		{name: "invalid IPv4 length", settings: &Settings{HostIPAddresses: []datatype.Address{valid, {Family: datatype.AddressFamilyIPv4, Value: []byte{192, 0, 2}}}}, wantErr: "HostIPAddresses[1]"},
		{name: "invalid IPv6 length", settings: &Settings{HostIPAddresses: []datatype.Address{{Family: datatype.AddressFamilyIPv6, Value: make([]byte, 15)}}}, wantErr: "HostIPAddresses[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.settings.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want %q", err, tc.wantErr)
			}
			machine, newErr := New(tc.settings)
			if (newErr == nil) != (tc.wantErr == "") || (machine != nil) != (tc.wantErr == "") {
				t.Fatalf("New() = (%v, %v), want error %q", machine, newErr, tc.wantErr)
			}
			if machine != nil && machine.Settings() != tc.settings {
				t.Fatal("New() did not retain the supplied Settings pointer")
			}
		})
	}
}
