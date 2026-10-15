package dnsdiam

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type lookupKey struct {
	name string
	typ  RRType
}
type fakeResolver struct {
	answers map[lookupKey]Answer
	errors  map[lookupKey]error
	queries []lookupKey
	before  func(lookupKey)
}

func (f *fakeResolver) Lookup(ctx context.Context, name string, typ RRType) (Answer, error) {
	if err := ctx.Err(); err != nil {
		return Answer{}, err
	}
	k := lookupKey{name, typ}
	f.queries = append(f.queries, k)
	if f.before != nil {
		f.before(k)
	}
	if err := f.errors[k]; err != nil {
		return Answer{}, err
	}
	a, ok := f.answers[k]
	if !ok {
		return Answer{RCode: RCodeSuccess, ReceivedAt: epoch}, nil
	}
	return a, nil
}

var epoch = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func testDiscoverer(t *testing.T, f *fakeResolver, now func() time.Time, rand func(int) int) *Discoverer {
	t.Helper()
	if now == nil {
		now = func() time.Time { return epoch }
	}
	d, err := New(Config{Resolver: f, Now: now, RandIntn: rand})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func nap(name, service, flags, replacement string, ttl uint32) Record {
	return Record{Name: name, Type: TypeNAPTR, TTL: ttl, NAPTR: &NAPTR{Service: service, Flags: flags, Replacement: replacement}}
}
func srv(name, host string, port, priority, weight uint16, ttl uint32) Record {
	return Record{Name: name, Type: TypeSRV, TTL: ttl, SRV: &SRV{Target: host, Port: port, Priority: priority, Weight: weight}}
}
func address(name, ip string, ttl uint32) Record {
	a := netip.MustParseAddr(ip)
	typ := TypeA
	if a.Is6() {
		typ = TypeAAAA
	}
	return Record{Name: name, Type: typ, TTL: ttl, Address: a}
}
func answer(records ...Record) Answer {
	return Answer{Records: records, ReceivedAt: epoch, RCode: RCodeSuccess}
}
func basicAnswers() map[lookupKey]Answer {
	return map[lookupKey]Answer{
		{"example.net.", TypeNAPTR}:               answer(nap("example.net.", "aaa+ap4:diameter.tls.tcp", "s", "_diameters._tcp.example.net.", 120)),
		{"_diameters._tcp.example.net.", TypeSRV}: answer(srv("_diameters._tcp.example.net.", "peer.example.net.", 7777, 0, 1, 60)),
		{"peer.example.net.", TypeA}:              answer(address("peer.example.net.", "192.0.2.1", 10)),
		{"peer.example.net.", TypeAAAA}:           answer(address("peer.example.net.", "2001:db8::1", 30)),
	}
}

func TestDiscoveryRejectsAliasDelegationAndExhaustedBudget(t *testing.T) {
	t.Run("negative alias policy", func(t *testing.T) {
		f := &fakeResolver{answers: basicAnswers()}
		f.answers[lookupKey{"example.net.", TypeNAPTR}] = Answer{RCode: RCodeNameError, ReceivedAt: epoch, Records: []Record{{Name: "example.net.", Type: TypeCNAME, TTL: 60, CNAME: "other.org."}}}
		_, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("negative external alias accepted: %v", err)
		}
	})
	t.Run("future receipt", func(t *testing.T) {
		f := &fakeResolver{answers: basicAnswers()}
		for key, a := range f.answers {
			a.ReceivedAt = epoch.Add(time.Hour)
			f.answers[key] = a
		}
		_, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("future receipt accepted: %v", err)
		}
	})
	t.Run("alias policy", func(t *testing.T) {
		f := &fakeResolver{answers: basicAnswers()}
		f.answers[lookupKey{"example.net.", TypeNAPTR}] = answer(Record{Name: "example.net.", Type: TypeCNAME, TTL: 60, CNAME: "other.org."})
		f.answers[lookupKey{"other.org.", TypeNAPTR}] = answer(nap("other.org.", "aaa+ap4:diameter.tls.tcp", "a", "peer.example.net.", 60))
		_, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("external alias accepted: %v", err)
		}
	})
	t.Run("partial budget", func(t *testing.T) {
		f := &fakeResolver{answers: basicAnswers()}
		f.answers[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", "aaa+ap4:diameter.tls.tcp", "a", "peer.example.net.", 60), nap("example.net.", "aaa+ap4:diameter.tls.tcp", "a", "second.example.net.", 60))
		d, err := New(Config{Resolver: f, Now: func() time.Time { return epoch }, MaxQueries: 4})
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
		if !errors.Is(err, ErrLimit) || len(got) > 0 {
			t.Fatalf("incomplete search returned candidates: %v %v", got, err)
		}
	})
}

func TestNAPTRNonterminalServiceOwner(t *testing.T) {
	f := &fakeResolver{answers: basicAnswers()}
	f.answers[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", "aaa+ap4:diameter.tls.tcp", "", "_delegate.example.net.", 60))
	f.answers[lookupKey{"_delegate.example.net.", TypeNAPTR}] = answer(nap("_delegate.example.net.", "aaa+ap4:diameter.tls.tcp", "a", "peer.example.net.", 60))
	got, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
	if err != nil || len(got) != 1 {
		t.Fatalf("valid NAPTR owner rejected: %v %v", got, err)
	}
}

func TestDiscoverUsesAddressesPortAndEarliestDeadline(t *testing.T) {
	f := &fakeResolver{answers: basicAnswers()}
	now := epoch.Add(3 * time.Second)
	d := testDiscoverer(t, f, func() time.Time { return now }, func(int) int { return 0 })
	c, err := d.Discover(context.Background(), Request{Realm: "EXAMPLE.NET.", ApplicationID: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 {
		t.Fatalf("candidates=%v", c)
	}
	x := c[0]
	if x.Host != "peer.example.net" || x.Realm != "example.net" || x.Port != 7777 || x.Transport != TLS {
		t.Fatalf("candidate=%+v", x)
	}
	if x.TTL != 7*time.Second || !x.ExpiresAt.Equal(epoch.Add(10*time.Second)) {
		t.Fatalf("ttl=%v expires=%v", x.TTL, x.ExpiresAt)
	}
	if !reflect.DeepEqual(x.Addresses, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}) {
		t.Fatalf("addresses=%v", x.Addresses)
	}
	if !reflect.DeepEqual(x.Names, []string{"example.net", "_diameters._tcp.example.net", "peer.example.net"}) {
		t.Fatalf("names=%v", x.Names)
	}
}

func TestDiscoveryAbsenceOnlyFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		root     Answer
		failure  error
		want     error
		fallback bool
	}{
		{"nodata", answer(), nil, nil, true},
		{"nxdomain", Answer{RCode: RCodeNameError, ReceivedAt: epoch}, nil, nil, true},
		{"servfail", Answer{RCode: 2, ReceivedAt: epoch}, nil, ErrDNS, false},
		{"timeout", Answer{}, context.DeadlineExceeded, context.DeadlineExceeded, false},
		{"wrong-app", answer(nap("example.net.", "aaa+ap1:diameter.tls.tcp", "s", "_diameters._tcp.example.net.", 120)), nil, ErrNoService, false},
		{"wrong-transport", answer(nap("example.net.", "aaa+ap4:diameter.sctp", "s", "_diameter._sctp.example.net.", 120)), nil, ErrNoService, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := basicAnswers()
			a[lookupKey{"example.net.", TypeNAPTR}] = tc.root
			f := &fakeResolver{answers: a, errors: map[lookupKey]error{{"example.net.", TypeNAPTR}: tc.failure}}
			c, err := testDiscoverer(t, f, nil, func(int) int { return 0 }).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
			if tc.want == nil && (err != nil || len(c) != 1) {
				t.Fatalf("c=%v err=%v", c, err)
			}
			queried := false
			for _, q := range f.queries {
				if q.typ == TypeSRV {
					queried = true
				}
			}
			if queried != tc.fallback {
				t.Fatalf("queries=%v fallback=%v", f.queries, tc.fallback)
			}
		})
	}
}

func TestWrongApplicationCannotUseGenericAdvertisement(t *testing.T) {
	a := basicAnswers()
	a[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", "aaa+ap1:diameter.tls.tcp", "s", "_diameters._tcp.example.net.", 120), nap("example.net.", "aaa:diameter.tls.tcp", "s", "_diameters._tcp.example.net.", 120))
	f := &fakeResolver{answers: a}
	_, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
	if !errors.Is(err, ErrNoService) {
		t.Fatalf("err=%v", err)
	}
	if len(f.queries) != 1 {
		t.Fatalf("queries=%v", f.queries)
	}
}

func TestNAPTRTerminalFlagsAndGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, service, flags, regexp string
		wantPort                     uint16
		want                         error
	}{
		{"address", "AaA+Ap4:DIAMETER.TLS.TCP", "A", "", 5868, nil},
		{"generic", "aaa", "a", "", 5868, nil},
		{"service-only", "aaa+ap4", "a", "", 5868, nil},
		{"leading-zero", "aaa+ap04:diameter.tls.tcp", "a", "", 0, ErrInvalid},
		{"overflow", "aaa+ap4294967296:diameter.tls.tcp", "a", "", 0, ErrInvalid},
		{"regexp", "aaa+ap4:diameter.tls.tcp", "a", "!x!y!", 0, ErrInvalid},
		{"unknown-flag", "aaa+ap4:diameter.tls.tcp", "u", "", 0, ErrNoService},
		{"multiple-flags", "aaa+ap4:diameter.tls.tcp", "sa", "", 0, ErrNoService},
		{"opaque-protocol", "aaa+ap4:diameter.tls.tcp.extra", "a", "", 0, ErrNoService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nap("example.net.", tc.service, tc.flags, "peer.example.net.", 100)
			r.NAPTR.Regexp = tc.regexp
			a := basicAnswers()
			a[lookupKey{"example.net.", TypeNAPTR}] = answer(r)
			c, err := testDiscoverer(t, &fakeResolver{answers: a}, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err=%v want=%v", err, tc.want)
				}
				return
			}
			if err != nil || len(c) != 1 || c[0].Port != tc.wantPort {
				t.Fatalf("c=%v err=%v", c, err)
			}
		})
	}
}

func TestNAPTRBacktracksWithoutSwitchingProtocol(t *testing.T) {
	a := basicAnswers()
	first := nap("example.net.", "aaa+ap4:diameter.tls.tcp", "", "delegate.example.net.", 100)
	first.NAPTR.Preference = 1
	backup := nap("example.net.", "aaa+ap4:diameter.tls.tcp", "a", "peer.example.net.", 100)
	backup.NAPTR.Preference = 2
	a[lookupKey{"example.net.", TypeNAPTR}] = answer(first, backup)
	a[lookupKey{"delegate.example.net.", TypeNAPTR}] = answer(nap("delegate.example.net.", "aaa+ap4:diameter.tcp", "a", "wrong.example.net.", 100))
	f := &fakeResolver{answers: a}
	c, err := testDiscoverer(t, f, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4, Transports: []Transport{TLS, TCP}})
	if err != nil || len(c) != 1 || c[0].Host != "peer.example.net" || c[0].Transport != TLS {
		t.Fatalf("c=%v err=%v", c, err)
	}
	for _, q := range f.queries {
		if q.name == "wrong.example.net." {
			t.Fatalf("switched protocol: %v", f.queries)
		}
	}
}

func TestSRVInclusiveWeightAndPriority(t *testing.T) {
	a := basicAnswers()
	a[lookupKey{"_diameters._tcp.example.net.", TypeSRV}] = answer(
		srv("_diameters._tcp.example.net.", "later.example.net.", 9999, 1, 65535, 100),
		srv("_diameters._tcp.example.net.", "weighted.example.net.", 7778, 0, 1, 100),
		srv("_diameters._tcp.example.net.", "peer.example.net.", 7777, 0, 0, 100))
	a[lookupKey{"weighted.example.net.", TypeA}] = answer(address("weighted.example.net.", "192.0.2.2", 30))
	a[lookupKey{"later.example.net.", TypeA}] = answer(address("later.example.net.", "192.0.2.3", 30))
	f := &fakeResolver{answers: a}
	var bounds []int
	c, err := testDiscoverer(t, f, nil, func(n int) int { bounds = append(bounds, n); return 0 }).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
	if err != nil || len(c) != 3 {
		t.Fatalf("c=%v err=%v", c, err)
	}
	if c[0].Host != "peer.example.net" || c[1].Host != "weighted.example.net" || c[2].Host != "later.example.net" {
		t.Fatalf("order=%v", c)
	}
	if len(bounds) == 0 || bounds[0] != 2 {
		t.Fatalf("RNG bounds=%v want first 2 (inclusive [0,1])", bounds)
	}
}

func TestSRVUnavailableAndAliasCannotDial(t *testing.T) {
	for _, target := range []string{".", "alias.example.net."} {
		t.Run(target, func(t *testing.T) {
			a := basicAnswers()
			a[lookupKey{"_diameters._tcp.example.net.", TypeSRV}] = answer(srv("_diameters._tcp.example.net.", target, 7777, 0, 1, 100))
			a[lookupKey{"alias.example.net.", TypeA}] = answer(Record{Name: "alias.example.net.", Type: TypeCNAME, TTL: 50, CNAME: "peer.example.net."})
			c, err := testDiscoverer(t, &fakeResolver{answers: a}, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
			if err == nil || len(c) != 0 {
				t.Fatalf("c=%v err=%v", c, err)
			}
		})
	}
}

func TestAddressAliasTTLAndZeroHighBitTTL(t *testing.T) {
	for _, ttl := range []uint32{2, 0, 0x80000001} {
		t.Run(time.Duration(ttl).String(), func(t *testing.T) {
			a := basicAnswers()
			a[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", "aaa+ap4:diameter.tls.tcp", "a", "alias.example.net.", 100))
			a[lookupKey{"alias.example.net.", TypeA}] = answer(Record{Name: "alias.example.net.", Type: TypeCNAME, TTL: ttl, CNAME: "peer.example.net."})
			a[lookupKey{"alias.example.net.", TypeAAAA}] = answer()
			c, err := testDiscoverer(t, &fakeResolver{answers: a}, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
			want := time.Duration(0)
			if ttl == 2 {
				want = 2 * time.Second
			}
			if err != nil || len(c) != 1 || c[0].TTL != want {
				t.Fatalf("c=%v err=%v wantTTL=%v", c, err, want)
			}
		})
	}
}

func TestDiscoveryBudgetsAndAuthentication(t *testing.T) {
	a := basicAnswers()
	a[lookupKey{"example.net.", TypeNAPTR}] = answer(nap("example.net.", "aaa+ap4:diameter.tls.tcp", "", "example.net.", 100))
	_, err := testDiscoverer(t, &fakeResolver{answers: a}, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("loop err=%v", err)
	}
	_, err = testDiscoverer(t, &fakeResolver{answers: basicAnswers()}, nil, nil).Discover(context.Background(), Request{Realm: "example.net", ApplicationID: 4, RequireAuthenticated: true})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("auth err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = testDiscoverer(t, &fakeResolver{answers: basicAnswers()}, nil, nil).Discover(ctx, Request{Realm: "example.net", ApplicationID: 4})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}
