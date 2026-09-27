package service

import (
	"testing"
	"time"
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
