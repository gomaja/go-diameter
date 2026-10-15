package dnsdiam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"
)

// DNSConfig selects literal-IP nameservers or a Unix resolv.conf file.
type DNSConfig struct {
	Servers    []string
	ResolvConf string
	Timeout    time.Duration
	Attempts   int
	Network    string
	TrustAD    bool
	Now        func() time.Time
}

const (
	maxDNSRecords = 1024
	maxDNSCache   = 1024
	maxDNSServers = 8
	maxDNSTimeout = 30 * time.Second
)

type dnsKey struct {
	name   string
	rrtype RRType
}
type dnsEntry struct {
	ready   chan struct{}
	answer  Answer
	err     error
	expires time.Time
}
type dnsResolver struct {
	servers  []string
	timeout  time.Duration
	attempts int
	network  string
	trustAD  bool
	now      func() time.Time
	mu       sync.Mutex
	entries  map[dnsKey]*dnsEntry
}

// NewResolver creates a concurrent resolver using the Codeberg DNS client.
// Servers must contain literal IP addresses, optionally with a port. If they
// are omitted, ResolvConf defaults to /etc/resolv.conf. Search suffixes are
// never applied. The default timeout is two seconds, with two attempts per
// server. Attempts cannot exceed three (RFC 9520 §3.1).
// TrustAD trusts a validating resolver's AD assertion; it does not perform
// DNSSEC validation locally (RFC 6840 §§5.7–5.8).
func NewResolver(cfg DNSConfig) (Resolver, error) {
	if cfg.Timeout < 0 || cfg.Timeout > maxDNSTimeout || cfg.Attempts < 0 || cfg.Attempts > 3 {
		return nil, fmt.Errorf("%w: timeout or attempt limit", ErrInvalid)
	}
	servers := cfg.Servers
	if len(servers) == 0 {
		path := cfg.ResolvConf
		if path == "" {
			path = "/etc/resolv.conf"
		}
		c, err := dnsconf.FromFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: resolver configuration: %w", ErrInvalid, err)
		}
		servers = c.Servers
		if cfg.Timeout == 0 {
			cfg.Timeout = time.Duration(min(c.Timeout, 30)) * time.Second
		}
		if cfg.Attempts == 0 {
			cfg.Attempts = min(c.Attempts, 3)
		}
		if cfg.Network == "" {
			cfg.Network = c.Network
		}
	}
	if len(servers) == 0 || len(servers) > maxDNSServers {
		return nil, fmt.Errorf("%w: require one to eight nameservers", ErrInvalid)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Attempts == 0 {
		cfg.Attempts = 2
	}
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	if cfg.Network != "udp" && cfg.Network != "tcp" {
		return nil, fmt.Errorf("%w: DNS network must be udp or tcp", ErrInvalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &dnsResolver{timeout: cfg.Timeout, attempts: cfg.Attempts, network: cfg.Network, trustAD: cfg.TrustAD, now: cfg.Now, entries: make(map[dnsKey]*dnsEntry)}
	seen := make(map[string]bool)
	for _, server := range servers {
		normalized, err := dnsServer(server)
		if err != nil {
			return nil, fmt.Errorf("%w: nameserver %q: %w", ErrInvalid, server, err)
		}
		if !seen[normalized] {
			r.servers = append(r.servers, normalized)
			seen[normalized] = true
		}
	}
	return r, nil
}

func dnsServer(s string) (string, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(a.String(), "53"), nil
	}
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return "", err
	}
	if a.Port() == 0 {
		return "", errors.New("zero port")
	}
	return a.String(), nil
}

// dnsNameKey folds only ASCII letters (RFC 4343 §§2–3).
func dnsNameKey(name string) string {
	name = strings.TrimSuffix(name, ".") + "."
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func (r *dnsResolver) Lookup(ctx context.Context, name string, rrtype RRType) (Answer, error) {
	if ctx == nil {
		return Answer{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return Answer{}, err
	}
	if name == "" {
		return Answer{}, fmt.Errorf("%w: empty DNS name", ErrInvalid)
	}
	name = strings.TrimSuffix(name, ".") + "."
	if len(name) > 254 || !dnsutil.IsName(name) || strings.ContainsAny(name, "\x00\r\n\\") {
		return Answer{}, fmt.Errorf("%w: invalid absolute DNS name", ErrInvalid)
	}
	switch rrtype {
	case TypeNAPTR, TypeSRV, TypeA, TypeAAAA, TypeCNAME:
	default:
		return Answer{}, fmt.Errorf("%w: unsupported DNS record type %s", ErrInvalid, strconv.Itoa(int(rrtype)))
	}
	key := dnsKey{dnsNameKey(name), rrtype}
	for {
		r.mu.Lock()
		now := r.now()
		if entry, ok := r.entries[key]; ok {
			if entry.ready != nil {
				ready := entry.ready
				r.mu.Unlock()
				select {
				case <-ready:
					continue
				case <-ctx.Done():
					return Answer{}, ctx.Err()
				}
			}
			if now.Before(entry.expires) {
				a, e := cloneDNSAnswer(entry.answer), entry.err
				r.mu.Unlock()
				return a, e
			}
			delete(r.entries, key)
		}
		if len(r.entries) >= maxDNSCache {
			for k, e := range r.entries {
				if e.ready == nil && !now.Before(e.expires) {
					delete(r.entries, k)
				}
			}
		}
		if len(r.entries) >= maxDNSCache {
			r.mu.Unlock()
			return Answer{}, fmt.Errorf("%w: %w", ErrDNS, ErrLimit)
		}
		entry := &dnsEntry{ready: make(chan struct{})}
		r.entries[key] = entry
		r.mu.Unlock()
		a, e := r.lookup(ctx, name, rrtype)
		expires := a.NegativeExpiresAt
		// A cached negative response cannot extend its accompanying alias lifetimes
		// (RFC 1034 §3.2.1; RFC 6604 §3 preserves final-cycle NXDOMAIN).
		if !expires.IsZero() {
			for _, rr := range a.Records {
				deadline := a.ReceivedAt.Add(time.Duration(rr.TTL) * time.Second)
				if deadline.Before(expires) {
					expires = deadline
				}
			}
		}
		if e != nil && ctx.Err() == nil {
			// RFC 9520 §3.2: hold resolution failures for at least one second;
			// matching outgoing resolution is suppressed until this deadline.
			expires = r.now().Add(time.Second)
		}
		r.mu.Lock()
		ready := entry.ready
		entry.ready = nil
		if expires.IsZero() || !r.now().Before(expires) {
			delete(r.entries, key)
		} else {
			entry.answer = cloneDNSAnswer(a)
			entry.err = e
			entry.expires = expires
		}
		close(ready)
		r.mu.Unlock()
		return a, e
	}
}

func cloneDNSAnswer(a Answer) Answer {
	a.Records = append([]Record(nil), a.Records...)
	for i := range a.Records {
		rr := &a.Records[i]
		if rr.NAPTR != nil {
			v := *rr.NAPTR
			rr.NAPTR = &v
		}
		if rr.SRV != nil {
			v := *rr.SRV
			rr.SRV = &v
		}
	}
	return a
}

func (r *dnsResolver) lookup(ctx context.Context, name string, rrtype RRType) (Answer, error) {
	var last error
	for _, server := range r.servers {
		for range r.attempts {
			if err := ctx.Err(); err != nil {
				return Answer{}, err
			}
			q := dns.NewMsg(name, uint16(rrtype))
			q.AuthenticatedData = r.trustAD
			m, err := r.exchange(ctx, q, r.network, server)
			if err == nil {
				err = validateDNSResponse(q, m)
			}
			if err == nil && m.Truncated && r.network == "udp" {
				// RFC 7766 §6.1.3.2: retry truncated UDP answers over TCP.
				q.Data = nil // Repack the query independently of the received buffer.
				m, err = r.exchange(ctx, q, "tcp", server)
				if err == nil {
					err = validateDNSResponse(q, m)
				}
			}
			if err == nil && m.Truncated {
				err = errors.New("truncated final DNS response")
			}
			if err == nil {
				a, convertErr := r.convert(m, rrtype)
				if convertErr == nil {
					return a, nil
				}
				err = convertErr
			}
			if cause := ctx.Err(); cause != nil {
				return Answer{}, cause
			}
			last = err
		}
	}
	return Answer{}, fmt.Errorf("%w: %w", ErrDNS, last)
}

func (r *dnsResolver) exchange(ctx context.Context, q *dns.Msg, network, server string) (*dns.Msg, error) {
	queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(queryCtx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(queryCtx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetWriteDeadline(time.Now().Add(r.timeout)); err != nil {
		return nil, err
	}
	c := &dns.Client{Transport: &dns.Transport{ReadTimeout: r.timeout, WriteTimeout: r.timeout}}
	m, _, err := c.ExchangeWithConn(queryCtx, q, conn)
	// An adapter's own timeout is a cacheable resolution failure. A caller's
	// canceled/deadline context is never cached.
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return m, err
}

func validateDNSResponse(q, m *dns.Msg) error {
	// RFC 1035 §§4.1.1–4.1.2; RFC 9619 §4: require exactly one
	// correlated IN question, including the opcode, before consuming answers.
	if m == nil || q == nil || !m.Response || m.ID != q.ID || m.Opcode != q.Opcode || len(m.Question) != 1 || len(q.Question) != 1 {
		return errors.New("uncorrelated DNS response")
	}
	question, want := m.Question[0], q.Question[0]
	if question.Header().Class != dns.ClassINET || dns.RRToType(question) != dns.RRToType(want) || dnsNameKey(question.Header().Name) != dnsNameKey(want.Header().Name) {
		return errors.New("DNS response question mismatch")
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return fmt.Errorf("DNS response code %d", m.Rcode)
	}
	return nil
}

func dnsTTL(ttl uint32) uint32 {
	if ttl > 0x7fffffff {
		return 0
	}
	return ttl
} // RFC 2181 §8.

func (r *dnsResolver) convert(m *dns.Msg, rrtype RRType) (Answer, error) {
	if len(m.Answer)+len(m.Ns)+len(m.Extra) > maxDNSRecords {
		return Answer{}, ErrLimit
	}
	a := Answer{RCode: RCode(m.Rcode), ReceivedAt: r.now(), Authenticated: r.trustAD && m.AuthenticatedData}
	hasRequested := false
	for _, raw := range m.Answer {
		h := raw.Header()
		if h.Class != dns.ClassINET {
			continue
		}
		rr := Record{Name: h.Name, TTL: dnsTTL(h.TTL)}
		switch v := raw.(type) {
		case *dns.NAPTR:
			rr.Type = TypeNAPTR
			rr.NAPTR = &NAPTR{v.Order, v.Preference, v.Flags, v.Service, v.Regexp, v.Replacement}
		case *dns.SRV:
			rr.Type = TypeSRV
			rr.SRV = &SRV{v.Priority, v.Weight, v.Port, v.Target}
		case *dns.A:
			rr.Type = TypeA
			rr.Address = v.Addr
			if !rr.Address.Is4() {
				return Answer{}, errors.New("invalid A address")
			}
		case *dns.AAAA:
			rr.Type = TypeAAAA
			rr.Address = v.Addr
			if !rr.Address.Is6() {
				return Answer{}, errors.New("invalid AAAA address")
			}
		case *dns.CNAME:
			rr.Type = TypeCNAME
			rr.CNAME = v.Target
		default:
			continue
		}
		if rr.Type == rrtype {
			hasRequested = true
		}
		a.Records = append(a.Records, rr)
	}
	if m.Rcode == dns.RcodeNameError || !hasRequested {
		// RFC 2308 §§2.1–2.2 distinguishes negative answers from
		// referrals. This stub requires a complete answer from an
		// authoritative server or recursive resolver before reporting absence.
		if !m.Authoritative && !m.RecursionAvailable {
			return Answer{}, errors.New("incomplete negative DNS response")
		}
		hasSOA, hasNS := false, false
		for _, raw := range m.Ns {
			if raw.Header().Class != dns.ClassINET {
				continue
			}
			switch raw.(type) {
			case *dns.SOA:
				hasSOA = true
			case *dns.NS:
				hasNS = true
			}
		}
		if m.Rcode == dns.RcodeSuccess && !m.Authoritative && hasNS && !hasSOA {
			return Answer{}, errors.New("DNS referral is not a complete answer")
		}
		// RFC 2308 §§3,5: negative TTL is min(SOA TTL, SOA.MINIMUM).
		// No SOA means no negative caching. CNAME records remain in NXDOMAIN.
		for _, raw := range m.Ns {
			if soa, ok := raw.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET {
				ttl := min(dnsTTL(soa.Hdr.TTL), dnsTTL(soa.Minttl))
				if ttl > 0 {
					expiry := a.ReceivedAt.Add(time.Duration(ttl) * time.Second)
					if a.NegativeExpiresAt.IsZero() || expiry.Before(a.NegativeExpiresAt) {
						a.NegativeExpiresAt = expiry
					}
				}
			}
		}
	}
	return a, nil
}
