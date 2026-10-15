package dnsdiam

import (
	"context"
	"testing"
	"time"
)

func FuzzDiscovery(f *testing.F) {
	f.Add("aaa+ap4:diameter.tls.tcp", "s", "_diameters._tcp.example.net.", uint32(60))
	f.Add("aaa+ap0004:diameter.tcp", "", "example.net.", uint32(0))
	f.Add("aaa:diameter.dtls", "a", "peer.example.net.", uint32(0x80000000))
	f.Fuzz(func(t *testing.T, service, flags, replacement string, ttl uint32) {
		if len(service)+len(flags)+len(replacement) > 1024 {
			t.Skip()
		}
		resolver := &fakeResolver{answers: basicAnswers()}
		resolver.answers[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", service, flags, replacement, ttl))
		d, err := New(Config{Resolver: resolver, Now: func() time.Time { return epoch }, RandIntn: func(int) int { return 0 }, MaxQueries: 8, MaxDepth: 4, MaxCandidates: 4})
		if err != nil {
			t.Fatal(err)
		}
		candidates, err := d.Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
		if len(resolver.queries) > 8 || len(candidates) > 4 {
			t.Fatal("unbounded discovery")
		}
		if err != nil && len(candidates) != 0 {
			t.Fatal("failed discovery returned usable candidates")
		}
		for _, candidate := range candidates {
			if candidate.Transport != TLS || candidate.ApplicationID != 4 || candidate.Realm != "example.net" || len(candidate.Addresses) == 0 || candidate.ExpiresAt.IsZero() {
				t.Fatalf("invalid successful candidate: %+v", candidate)
			}
			if candidate.TTL < 0 || candidate.ExpiresAt.After(epoch.Add(120*time.Second)) {
				t.Fatalf("inflated expiry: %+v", candidate)
			}
		}
	})
}
