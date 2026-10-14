package dnsdiam

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// authoritative starts independent UDP and TCP listeners at the same address.
// The handler receives the actual query decoded from the socket.
func authoritative(t *testing.T, handler func(*dns.Msg, string) *dns.Msg) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			b := make([]byte, 65535)
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			q := &dns.Msg{Data: b[:n]}
			if q.Unpack() != nil {
				continue
			}
			r := handler(q, "udp")
			if r == nil {
				continue
			}
			if e = r.Pack(); e != nil {
				t.Error(e)
				continue
			}
			if _, e = udp.WriteTo(r.Data, a); e != nil {
				t.Error(e)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var sz [2]byte
				if _, e := io.ReadFull(c, sz[:]); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(sz[:]))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				q := &dns.Msg{Data: b}
				if q.Unpack() != nil {
					return
				}
				r := handler(q, "tcp")
				if r == nil {
					return
				}
				if e := r.Pack(); e != nil {
					t.Error(e)
					return
				}
				binary.BigEndian.PutUint16(sz[:], uint16(len(r.Data)))
				if _, e := c.Write(append(sz[:], r.Data...)); e != nil {
					t.Error(e)
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close(); wg.Wait() })
	return tcp.Addr().String()
}

func reply(q *dns.Msg) *dns.Msg {
	return &dns.Msg{MsgHeader: dns.MsgHeader{ID: q.ID, Response: true, Authoritative: true}, Question: q.Question}
}

func adapter(t *testing.T, addr string, cfg DNSConfig) Resolver {
	t.Helper()
	cfg.Servers = []string{addr}
	if cfg.Attempts == 0 {
		cfg.Attempts = 1
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = time.Second
	}
	r, e := NewResolver(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestResolverConvertsAnswerRecords(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		if q.Question[0].Header().Name != "Example.test." {
			t.Errorf("query name %q", q.Question[0].Header().Name)
		}
		r := reply(q)
		r.AuthenticatedData = true
		h := dns.Header{Name: "Example.test.", Class: dns.ClassINET, TTL: 42}
		r.Answer = []dns.RR{&dns.NAPTR{Hdr: h, NAPTR: rdata.NAPTR{Order: 10, Preference: 20, Flags: "S", Service: "aaa+ap4:diameter.tls.tcp", Replacement: "_diameters._tcp.example.test."}}, &dns.SRV{Hdr: h, SRV: rdata.SRV{Priority: 3, Weight: 5, Port: 5868, Target: "peer.example.test."}}, &dns.A{Hdr: h, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}, &dns.AAAA{Hdr: h, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")}}, &dns.CNAME{Hdr: h, CNAME: rdata.CNAME{Target: "alias.example.test."}}}
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.Header{Name: h.Name, Class: dns.ClassCHAOS, TTL: 77}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.99")}})
		r.Extra = []dns.RR{&dns.A{Hdr: h, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.88")}}}
		return r
	})
	for _, trusted := range []bool{false, true} {
		r := adapter(t, addr, DNSConfig{TrustAD: trusted, Now: func() time.Time { return now }})
		a, e := r.Lookup(context.Background(), "Example.test", TypeNAPTR)
		if e != nil {
			t.Fatal(e)
		}
		if len(a.Records) != 5 || a.ReceivedAt != now || a.Authenticated != trusted {
			t.Fatalf("answer %+v", a)
		}
		if a.Records[0].NAPTR.Order != 10 || a.Records[0].NAPTR.Preference != 20 || a.Records[0].NAPTR.Service != "aaa+ap4:diameter.tls.tcp" || a.Records[1].SRV.Port != 5868 || a.Records[2].Address.String() != "192.0.2.1" || a.Records[3].Address.String() != "2001:db8::1" || a.Records[4].CNAME != "alias.example.test." {
			t.Fatalf("records %+v", a.Records)
		}
		for _, rr := range a.Records {
			if rr.TTL != 42 {
				t.Fatal(rr)
			}
		}
	}
}

func TestResolverRejectsUncorrelatedResponses(t *testing.T) {
	cases := map[string]func(*dns.Msg){"id": func(r *dns.Msg) { r.ID++ }, "qr": func(r *dns.Msg) { r.Response = false }, "opcode": func(r *dns.Msg) { r.Opcode = 2 }, "name": func(r *dns.Msg) { r.Question[0].Header().Name = "other.test." }, "type": func(r *dns.Msg) { r.Question = []dns.RR{&dns.AAAA{Hdr: *r.Question[0].Header()}} }, "class": func(r *dns.Msg) { r.Question[0].Header().Class = dns.ClassCHAOS }, "empty": func(r *dns.Msg) { r.Question = nil }, "multiple": func(r *dns.Msg) { r.Question = append(r.Question, r.Question[0]) }, "servfail": func(r *dns.Msg) { r.Rcode = 2 }, "refused": func(r *dns.Msg) { r.Rcode = 5 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { r := reply(q); mutate(r); return r })
			r := adapter(t, addr, DNSConfig{})
			if _, e := r.Lookup(context.Background(), "example.test.", TypeA); !errors.Is(e, ErrDNS) {
				t.Fatalf("error %v", e)
			}
		})
	}
}

func TestResolverRetriesTruncationOverTCP(t *testing.T) {
	var mu sync.Mutex
	var networks []string
	addr := authoritative(t, func(q *dns.Msg, network string) *dns.Msg {
		if q.Response {
			t.Errorf("%s retry sent a DNS response instead of a query", network)
		}
		mu.Lock()
		networks = append(networks, network)
		mu.Unlock()
		r := reply(q)
		if network == "udp" {
			r.Truncated = true
		} else {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 10}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}
		}
		return r
	})
	r := adapter(t, addr, DNSConfig{})
	a, e := r.Lookup(context.Background(), "example.test", TypeA)
	if e != nil || len(a.Records) != 1 {
		t.Fatalf("answer %+v error %v", a, e)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(networks) != 2 || networks[0] != "udp" || networks[1] != "tcp" {
		t.Fatal(networks)
	}
}

func TestResolverTimeoutFailureIsCached(t *testing.T) {
	var calls atomic.Int32
	addr := authoritative(t, func(_ *dns.Msg, _ string) *dns.Msg { calls.Add(1); return nil })
	r := adapter(t, addr, DNSConfig{Timeout: 20 * time.Millisecond})
	for i := 0; i < 2; i++ {
		if _, e := r.Lookup(context.Background(), "timeout.test", TypeA); !errors.Is(e, ErrDNS) {
			t.Fatal(e)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("timeout failure sent %d queries", calls.Load())
	}
}

func TestResolverPositiveAndZeroNegativeTTLNotCached(t *testing.T) {
	for _, ttl := range []uint32{0, 0x80000000, 42} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			var calls atomic.Int32
			addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
				calls.Add(1)
				r := reply(q)
				r.Answer = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: ttl}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}
				return r
			})
			r := adapter(t, addr, DNSConfig{})
			for i := 0; i < 2; i++ {
				a, e := r.Lookup(context.Background(), "example.test", TypeA)
				if e != nil || len(a.Records) != 1 {
					t.Fatalf("%+v %v", a, e)
				}
				want := ttl
				if ttl == 0x80000000 {
					want = 0
				}
				if a.Records[0].TTL != want {
					t.Fatal(a.Records)
				}
			}
			if calls.Load() != 2 {
				t.Fatal(calls.Load())
			}
		})
	}
	var calls atomic.Int32
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		calls.Add(1)
		r := reply(q)
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 20}, SOA: rdata.SOA{Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 0}}}
		return r
	})
	r := adapter(t, addr, DNSConfig{})
	for i := 0; i < 2; i++ {
		_, _ = r.Lookup(context.Background(), "example.test", TypeA)
	}
	if calls.Load() != 2 {
		t.Fatalf("zero negative TTL cached: %d", calls.Load())
	}
}

func TestResolverConcurrentFailuresCoalesce(t *testing.T) {
	var calls atomic.Int32
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { calls.Add(1); r := reply(q); r.Rcode = 2; return r })
	r := adapter(t, addr, DNSConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := r.Lookup(context.Background(), "example.test", TypeA); !errors.Is(e, ErrDNS) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("failure emitted %d queries", calls.Load())
	}
}

func TestResolverRejectsTruncatedTCP(t *testing.T) {
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { r := reply(q); r.Truncated = true; return r })
	r := adapter(t, addr, DNSConfig{})
	if _, e := r.Lookup(context.Background(), "example.test", TypeA); !errors.Is(e, ErrDNS) {
		t.Fatal(e)
	}
}

func TestResolverCancellationClosesBlockedRead(t *testing.T) {
	queried := make(chan struct{}, 1)
	addr := authoritative(t, func(_ *dns.Msg, _ string) *dns.Msg { queried <- struct{}{}; return nil })
	r := adapter(t, addr, DNSConfig{Timeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := r.Lookup(ctx, "example.test", TypeA); done <- e }()
	<-queried
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cancellation left read blocked")
	}
	// Context cancellation must not create a resolution-failure hold.
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _, _ = r.Lookup(ctx2, "example.test", TypeA) }()
	select {
	case <-queried:
		cancel2()
	case <-time.After(time.Second):
		cancel2()
		t.Fatal("canceled lookup cached")
	}
}

func TestResolverNegativeCachePreservesExpiryAndAliases(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		calls.Add(1)
		r := reply(q)
		r.Rcode = 3
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 2}, CNAME: rdata.CNAME{Target: "missing.test."}}}
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 20}, SOA: rdata.SOA{Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: 10}}}
		return r
	})
	r := adapter(t, addr, DNSConfig{Now: func() time.Time { return now }})
	a, e := r.Lookup(context.Background(), "example.test", TypeA)
	if e != nil || a.RCode != RCodeNameError || len(a.Records) != 1 || a.NegativeExpiresAt != now.Add(10*time.Second) {
		t.Fatalf("%+v %v", a, e)
	}
	original := now
	now = now.Add(time.Second)
	b, e := r.Lookup(context.Background(), "EXAMPLE.TEST.", TypeA)
	if e != nil || b.ReceivedAt != original || b.NegativeExpiresAt != original.Add(10*time.Second) || calls.Load() != 1 {
		t.Fatalf("%+v %v calls %d", b, e, calls.Load())
	}
	b.Records[0].CNAME = "corrupted.test."
	b.Records[0].TTL = 100
	copyAnswer, e := r.Lookup(context.Background(), "example.test", TypeA)
	if e != nil || copyAnswer.Records[0].CNAME != "missing.test." || copyAnswer.Records[0].TTL != 2 {
		t.Fatalf("caller mutated cached answer: %+v %v", copyAnswer, e)
	}
	now = original.Add(2 * time.Second)
	_, e = r.Lookup(context.Background(), "example.test", TypeA)
	if e != nil || calls.Load() != 2 {
		t.Fatalf("alias expiry did not invalidate cache: %v calls %d", e, calls.Load())
	}
}

func TestResolverFailureHoldAndAttemptBound(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { calls.Add(1); r := reply(q); r.Rcode = 2; return r })
	r := adapter(t, addr, DNSConfig{Attempts: 3, Now: func() time.Time { return now }})
	for i := 0; i < 2; i++ {
		if _, e := r.Lookup(context.Background(), "example.test", TypeNAPTR); !errors.Is(e, ErrDNS) {
			t.Fatal(e)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("queries %d", calls.Load())
	}
	now = now.Add(time.Second)
	_, _ = r.Lookup(context.Background(), "example.test", TypeNAPTR)
	if calls.Load() != 6 {
		t.Fatalf("hold never expired: %d", calls.Load())
	}
}

func TestResolverNoSOAAndZeroTTLNotCached(t *testing.T) {
	for _, rcode := range []uint16{0, 3} {
		t.Run(string(rune('0'+rcode)), func(t *testing.T) {
			var calls atomic.Int32
			addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { calls.Add(1); r := reply(q); r.Rcode = rcode; return r })
			r := adapter(t, addr, DNSConfig{})
			for i := 0; i < 2; i++ {
				a, e := r.Lookup(context.Background(), "example.test", TypeA)
				if e != nil || a.RCode != RCode(rcode) || !a.NegativeExpiresAt.IsZero() {
					t.Fatalf("%+v %v", a, e)
				}
			}
			if calls.Load() != 2 {
				t.Fatal(calls.Load())
			}
		})
	}
}

func TestResolverConfigValidation(t *testing.T) {
	for _, cfg := range []DNSConfig{{Servers: []string{"dns.example.test"}}, {Servers: []string{"127.0.0.1:0"}}, {Servers: []string{"127.0.0.1:65536"}}, {Servers: []string{"127.0.0.1"}, Attempts: 4}, {Servers: []string{"127.0.0.1"}, Attempts: -1}, {Servers: []string{"127.0.0.1"}, Timeout: -1}, {Servers: []string{"127.0.0.1"}, Network: "tls"}} {
		if _, e := NewResolver(cfg); !errors.Is(e, ErrInvalid) {
			t.Fatalf("config %+v error %v", cfg, e)
		}
	}
	for _, server := range []string{"127.0.0.1", "[::1]:53", "::1", "192.0.2.1:5300"} {
		if _, e := NewResolver(DNSConfig{Servers: []string{server}}); e != nil {
			t.Fatal(server, e)
		}
	}
}

func TestResolverConfigFileNoSearchExpansion(t *testing.T) {
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		if q.Question[0].Header().Name != "short." {
			t.Errorf("search expansion: %q", q.Question[0].Header().Name)
		}
		return reply(q)
	})
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if e := os.WriteFile(path, []byte("nameserver "+addr+"\nsearch example.test\noptions use-vc attempts:99 timeout:999\n"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := NewResolver(DNSConfig{ResolvConf: path, Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Lookup(context.Background(), "short", TypeA); e != nil {
		t.Fatal(e)
	}
}

func TestResolverConcurrentLookups(t *testing.T) {
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg { return reply(q) })
	r := adapter(t, addr, DNSConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := r.Lookup(context.Background(), "example.test", TypeAAAA); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}

func TestResolverFixedWireReplies(t *testing.T) {
	fixtures := []struct {
		name, wire string
		valid      bool
	}{
		{"valid", "000084000001000100000000076578616d706c6504746573740000010001c00c000100010000002a0004c0000201", true},
		{"short_header", "000084000001", false},
		{"pointer_loop", "000084000001000000000000c00c00010001", false},
		{"short_address", "000084000001000100000000076578616d706c6504746573740000010001c00c000100010000002a0004c00002", false},
		{"wrong_question_type", "000084000001000000000000076578616d706c65047465737400001c0001", false},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			wire, e := hex.DecodeString(fixture.wire)
			if e != nil {
				t.Fatal(e)
			}
			socket, e := net.ListenPacket("udp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				b := make([]byte, 512)
				n, a, err := socket.ReadFrom(b)
				if err != nil || n < 2 {
					return
				}
				copy(wire[:2], b[:2])
				if _, err = socket.WriteTo(wire, a); err != nil {
					t.Error(err)
				}
			}()
			t.Cleanup(func() { _ = socket.Close(); <-done })
			r := adapter(t, socket.LocalAddr().String(), DNSConfig{})
			a, e := r.Lookup(context.Background(), "example.test", TypeA)
			if fixture.valid {
				if e != nil || len(a.Records) != 1 || a.Records[0].Address.String() != "192.0.2.1" || a.Records[0].TTL != 42 {
					t.Fatalf("%+v %v", a, e)
				}
			} else if !errors.Is(e, ErrDNS) {
				t.Fatalf("malformed response accepted: %+v %v", a, e)
			}
		})
	}
}

func TestResolverRejectsIncompleteTCPFrame(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b := make([]byte, 512)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte{0, 40, 0x12, 0x34, 0x84, 0})
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	r := adapter(t, ln.Addr().String(), DNSConfig{Network: "tcp"})
	if _, e := r.Lookup(context.Background(), "example.test", TypeA); !errors.Is(e, ErrDNS) {
		t.Fatal(e)
	}
}

func TestResolverAcceptsASCIICaseAndRootDot(t *testing.T) {
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		r := reply(q)
		r.Question[0].Header().Name = "EXAMPLE.TEST."
		return r
	})
	r := adapter(t, addr, DNSConfig{})
	if _, e := r.Lookup(context.Background(), "example.test", TypeA); e != nil {
		t.Fatal(e)
	}
}

func TestResolverLookupRejectsInvalidInput(t *testing.T) {
	r, e := NewResolver(DNSConfig{Servers: []string{"127.0.0.1:53"}})
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"", "a..test", "bad\x00.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 128)} {
		if _, e = r.Lookup(context.Background(), name, TypeA); !errors.Is(e, ErrInvalid) {
			t.Fatalf("name %q error %v", name, e)
		}
	}
	var nilContext context.Context
	if _, e = r.Lookup(nilContext, "example.test", TypeA); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = r.Lookup(context.Background(), "example.test", RRType(65000)); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = r.Lookup(ctx, "example.test", TypeA); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestResolverRejectsIncompleteNegativeResponses(t *testing.T) {
	for _, referral := range []bool{false, true} {
		t.Run(fmt.Sprint(referral), func(t *testing.T) {
			addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
				r := reply(q)
				r.Authoritative = false
				if referral {
					r.RecursionAvailable = true
					r.Ns = []dns.RR{&dns.NS{Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 20}, NS: rdata.NS{Ns: "ns.test."}}}
				}
				return r
			})
			r := adapter(t, addr, DNSConfig{})
			if _, e := r.Lookup(context.Background(), "example.test", TypeA); !errors.Is(e, ErrDNS) {
				t.Fatalf("incomplete negative accepted: %v", e)
			}
		})
	}
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		r := reply(q)
		r.Authoritative = false
		r.RecursionAvailable = true
		return r
	})
	r := adapter(t, addr, DNSConfig{})
	if _, e := r.Lookup(context.Background(), "example.test", TypeA); e != nil {
		t.Fatalf("recursive NODATA rejected: %v", e)
	}
}

func TestResolverLimitsRecordsAndCache(t *testing.T) {
	addr := authoritative(t, func(q *dns.Msg, _ string) *dns.Msg {
		r := reply(q)
		for range 1025 {
			r.Answer = append(r.Answer, &dns.A{Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 1}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}})
		}
		return r
	})
	r := adapter(t, addr, DNSConfig{Network: "tcp"})
	if _, e := r.Lookup(context.Background(), "example.test", TypeA); !errors.Is(e, ErrLimit) {
		t.Fatalf("record limit: %v", e)
	}
	concrete := r.(*dnsResolver)
	concrete.mu.Lock()
	for i := 0; i < 1024; i++ {
		concrete.entries[dnsKey{name: fmt.Sprintf("cache%d.test.", i), rrtype: TypeA}] = &dnsEntry{expires: time.Now().Add(time.Minute), err: ErrDNS}
	}
	concrete.mu.Unlock()
	if _, e := r.Lookup(context.Background(), "new.test", TypeA); !errors.Is(e, ErrLimit) {
		t.Fatalf("cache limit: %v", e)
	}
}
