package dnsdiam

import (
	"encoding/hex"
	"testing"
	"time"

	dns "codeberg.org/miekg/dns"
)

// Fixed wire seeds do not use the codec under test to form expected messages.
func FuzzResolverResponse(f *testing.F) {
	for _, seed := range []string{
		"123484000001000100000000076578616d706c6504746573740000010001c00c000100010000002a0004c0000201",
		"123484030001000000000000076578616d706c6504746573740000010001",
		"123484000001000000000000c00c00010001",                                                       // compression pointer cycle
		"123484000001000100000000076578616d706c6504746573740000010001c00c000100010000002a0004c00002", // short A
		"123484000002000000000000076578616d706c6504746573740000010001",                               // short second question
	} {
		b, e := hex.DecodeString(seed)
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		m := &dns.Msg{Data: append([]byte(nil), b...)}
		if m.Unpack() != nil {
			return
		}
		q := dns.NewMsg("example.test.", dns.TypeA)
		q.ID = 0x1234
		if validateDNSResponse(q, m) != nil {
			return
		}
		r := &dnsResolver{now: func() time.Time { return time.Unix(100, 0) }}
		a, e := r.convert(m, TypeA)
		if e != nil {
			return
		}
		if len(a.Records) > 1024 {
			t.Fatal("record bound bypassed")
		}
		for _, rr := range a.Records {
			if rr.TTL > 0x7fffffff {
				t.Fatal("high-bit TTL accepted")
			}
			if rr.Type == TypeA && !rr.Address.Is4() {
				t.Fatal("invalid A address")
			}
			if rr.Type == TypeAAAA && !rr.Address.Is6() {
				t.Fatal("invalid AAAA address")
			}
		}
	})
}

func FuzzResolverNameKey(f *testing.F) {
	for _, s := range []string{"Example.TEST", "example.test.", ".", "_diameter._tcp.example.test.", "\x00", "İ.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		key := dnsNameKey(s)
		if dnsNameKey(key) != key {
			t.Fatal("name normalization is not idempotent")
		}
	})
}
