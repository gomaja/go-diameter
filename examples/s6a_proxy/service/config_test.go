package service

import "testing"

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
