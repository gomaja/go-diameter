package sm

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
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

// Validate is the single configuration check behind New and peer.New, so it
// covers explicit capabilities as well as Host-IP-Address values (RFC 6733
// §6.11, Verified Erratum 4808).
func TestSettingsValidateCapabilities(t *testing.T) {
	vsai := func(members ...*diam.AVP) *diam.AVP {
		return diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: members})
	}
	vendor := diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415))
	auth := diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(16777216))
	for _, tc := range []struct {
		name    string
		groups  []*diam.AVP
		wantErr string
	}{
		{name: "one vendor and one application", groups: []*diam.AVP{vsai(vendor, auth)}},
		{name: "no vendor", groups: []*diam.AVP{vsai(auth)}, wantErr: "exactly one Vendor-Id"},
		{name: "two vendors", groups: []*diam.AVP{vsai(vendor, vendor, auth)}, wantErr: "exactly one Vendor-Id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := &Settings{
				OriginHost:                  "node.example",
				OriginRealm:                 "example",
				HostIPAddresses:             []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))},
				VendorSpecificApplicationID: tc.groups,
			}
			err := settings.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want %q", err, tc.wantErr)
			}
			machine, newErr := New(settings)
			if (newErr == nil) != (tc.wantErr == "") || (machine != nil) != (tc.wantErr == "") {
				t.Fatalf("New() = (%v, %v), want error %q", machine, newErr, tc.wantErr)
			}
		})
	}
}

// RFC 3539 §3.4.1 [1]: the default and minimum apply only to enabled watchdogs.
func TestSettingsWatchdogValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enabled  bool
		interval time.Duration
		timing   *watchdogTiming
		want     time.Duration
		wantErr  string
	}{
		{name: "disabled"},
		{name: "disabled negative", interval: -time.Second},
		{name: "disabled short", interval: time.Nanosecond},
		{name: "default", enabled: true, want: 30 * time.Second},
		{name: "minimum", enabled: true, interval: 6 * time.Second, want: 6 * time.Second},
		{name: "below minimum", enabled: true, interval: 6*time.Second - time.Nanosecond, wantErr: "watchdog interval 5.999999999s is below RFC 3539 §3.4.1 minimum 6s"},
		{name: "negative", enabled: true, interval: -time.Second, wantErr: "watchdog interval -1s is below RFC 3539 §3.4.1 minimum 6s"},
		{name: "override", enabled: true, interval: time.Millisecond, timing: &watchdogTiming{floor: time.Millisecond}, want: time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Settings{EnableWatchdog: tc.enabled, WatchdogInterval: tc.interval, watchdogTiming: tc.timing, WatchdogStream: 3}
			called := false
			cfg.OnWatchdogConnEvent = func(diam.Conn, WatchdogEvent) { called = true }
			sm, err := New(cfg)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("New error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sm.Settings() != cfg || cfg.WatchdogInterval != tc.interval {
				t.Fatal("New mutated or replaced caller settings")
			}
			if !tc.enabled {
				if sm.watchdog != nil {
					t.Fatal("disabled watchdog has policy")
				}
				return
			}
			if sm.watchdog == nil || sm.watchdog.twinit != tc.want || sm.watchdog.stream != 3 {
				t.Fatalf("policy = %+v, want Twinit %s, stream 3", sm.watchdog, tc.want)
			}
			_, jitter := tc.timing.parameters()
			if sm.watchdog.jitter != jitter {
				t.Fatalf("jitter = %s, want %s", sm.watchdog.jitter, jitter)
			}
			sm.watchdog.onEvent(nil, WatchdogRequestSent)
			if !called {
				t.Fatal("policy lost event callback")
			}
		})
	}
}
