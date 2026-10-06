package service

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestS6aProxyConfigCloneWithDefaults(t *testing.T) {
	src := &S6aProxyConfig{}

	got := src.CloneWithDefaults()
	if got == nil {
		t.Fatal("CloneWithDefaults returned nil")
	}
	if got.Protocol != "sctp" {
		t.Fatalf("Protocol = %q, want sctp", got.Protocol)
	}
	if got.Host != "protocol.s6a.proxy" {
		t.Fatalf("Host = %q, want protocol.s6a.proxy", got.Host)
	}
	if got.Realm != "realm.s6a.proxy" {
		t.Fatalf("Realm = %q, want realm.s6a.proxy", got.Realm)
	}
	if got.Retransmits != 3 {
		t.Fatalf("Retransmits = %d, want 3", got.Retransmits)
	}
	if got.WatchdogInterval != 7 {
		t.Fatalf("WatchdogInterval = %d, want 7", got.WatchdogInterval)
	}
	if src.Protocol != "" || src.Host != "" || src.Realm != "" {
		t.Fatal("CloneWithDefaults modified source config")
	}
}

func TestS6aProxyApplicationVendor(t *testing.T) {
	proxy, err := NewS6aProxy(&S6aProxyConfig{
		HssAddr: "127.0.0.1:3868", Protocol: "tcp", Host: "proxy.example", Realm: "example",
	})
	if err != nil {
		t.Fatal(err)
	}
	groups := proxy.smClient.VendorSpecificApplicationID
	if len(groups) != 1 {
		t.Fatalf("VSAI groups = %d, want 1", len(groups))
	}
	group, ok := groups[0].Data.(*diam.GroupedAVP)
	if !ok || len(group.AVP) != 2 {
		t.Fatalf("S6a VSAI = %v", groups[0])
	}
	var vendor, application uint32
	for _, child := range group.AVP {
		switch child.Code {
		case avp.VendorID:
			vendor = uint32(child.Data.(datatype.Unsigned32))
		case avp.AuthApplicationID:
			application = uint32(child.Data.(datatype.Unsigned32))
		}
	}
	if vendor != VENDOR_3GPP || application != diam.TGPP_S6A_APP_ID {
		t.Fatalf("S6a VSAI = {%d, %d}, want {%d, %d}", vendor, application, VENDOR_3GPP, diam.TGPP_S6A_APP_ID)
	}
}

func TestS6aProxyUsesConfiguredWatchdogInterval(t *testing.T) {
	for _, tc := range []struct {
		configured uint
		want       time.Duration
	}{{0, 7 * time.Second}, {11, 11 * time.Second}} {
		proxy, err := NewS6aProxy(&S6aProxyConfig{
			HssAddr: "127.0.0.1:3868", Protocol: "tcp",
			Host: "proxy.example", Realm: "example", WatchdogInterval: tc.configured,
		})
		if err != nil {
			t.Fatal(err)
		}
		if proxy.smClient.WatchdogInterval != tc.want {
			t.Errorf("configured %d: watchdog interval = %s, want %s", tc.configured, proxy.smClient.WatchdogInterval, tc.want)
		}
	}
}
