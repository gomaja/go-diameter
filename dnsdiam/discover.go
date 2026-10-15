package dnsdiam

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config selects a resolver and bounds the S-NAPTR search. A nil
// AllowDelegation permits only names within the requested realm; an explicit
// exception still requires certificate naming and role authorization.
type Config struct {
	Resolver                            Resolver
	Now                                 func() time.Time
	RandIntn                            func(int) int
	MaxQueries, MaxDepth, MaxCandidates int
	AllowDelegation                     func(realm, name string) bool
}

// Discoverer performs independent protocol searches (RFC 3958 §2.2.5). The
// supplied resolver and clock must be concurrency-safe. RNG calls are serialized.
type Discoverer struct {
	cfg      Config
	randomMu sync.Mutex
}

// New creates a discoverer. Resolver is explicit so test and application DNS
// traffic share the same configured resolution boundary.
func New(cfg Config) (*Discoverer, error) {
	if cfg.Resolver == nil {
		return nil, ErrInvalid
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RandIntn == nil {
		cfg.RandIntn = rand.IntN
	}
	if cfg.MaxQueries == 0 {
		cfg.MaxQueries = 64
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 16
	}
	if cfg.MaxCandidates == 0 {
		cfg.MaxCandidates = 128
	}
	if cfg.MaxQueries < 1 || cfg.MaxQueries > 4096 || cfg.MaxDepth < 1 || cfg.MaxDepth > 128 || cfg.MaxCandidates < 1 || cfg.MaxCandidates > 1024 {
		return nil, ErrInvalid
	}
	return &Discoverer{cfg: cfg}, nil
}

// Discover returns ordered attempts without caching DNS data. TTL zero
// candidates may be inspected but cannot authorize a managed lease.
func (d *Discoverer) Discover(ctx context.Context, request Request) ([]Candidate, error) {
	if d == nil || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	realm, err := absolute(request.Realm, false)
	if err != nil {
		return nil, err
	}
	request.Realm = identityName(realm)
	transports := slices.Clone(request.Transports)
	if len(transports) == 0 {
		transports = []Transport{TLS}
	}
	seen := make(map[Transport]bool)
	for _, transport := range transports {
		if !knownTransport(transport) || seen[transport] {
			return nil, fmt.Errorf("%w: transport %q", ErrInvalid, transport)
		}
		seen[transport] = true
	}
	s := search{d: d, ctx: ctx, request: request, realm: realm}
	root, err := s.lookup(realm, TypeNAPTR, false)
	if err != nil {
		return nil, err
	}
	var candidates []Candidate
	var failures []error
	for _, transport := range transports {
		var found []Candidate
		if len(root.records) == 0 {
			label := "_diameter._tcp."
			switch transport {
			case TLS:
				label = "_diameters._tcp."
			case SCTP:
				label = "_diameter._sctp."
			case DTLS:
				label = "_diameters._sctp."
			}
			found, err = s.resolveSRV(label+realm, transport, root.expires, root.names, NAPTR{})
		} else {
			found, err = s.walk(realm, root, transport, root.expires, root.names, make(map[string]bool), 0)
		}
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		if err != nil {
			failures = append(failures, err)
		}
		candidates = append(candidates, found...)
		if len(candidates) > d.cfg.MaxCandidates {
			return nil, ErrLimit
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if len(candidates) == 0 {
		return nil, errors.Join(append([]error{ErrNoService}, failures...)...)
	}
	return candidates, nil
}

func knownTransport(t Transport) bool { return t == TLS || t == DTLS || t == TCP || t == SCTP }

// absolute rejects escaped and non-ASCII labels; callers provide IDNA A-labels.
// Service owner names may contain underscores, host and realm identities may not.
func absolute(name string, service bool) (string, error) {
	for i := 0; i < len(name); i++ {
		if name[i] >= 128 {
			return "", ErrInvalid
		}
	}
	if name == "" {
		return "", ErrInvalid
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, c := range []byte(label) {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || service && c == '_' {
				continue
			}
			return "", ErrInvalid
		}
	}
	return strings.ToLower(name) + ".", nil
}
func identityName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
func ttlDeadline(received time.Time, ttl uint32) time.Time {
	// RFC 2181 §8: a wire TTL with its high bit set is zero, not a huge lease.
	if ttl&0x80000000 != 0 {
		ttl = 0
	}
	return received.Add(time.Duration(ttl) * time.Second)
}
func appendNames(names []string, values ...string) []string {
	next := slices.Clone(names)
	for _, value := range values {
		name := identityName(value)
		if !slices.Contains(next, name) {
			next = append(next, name)
		}
	}
	return next
}

type search struct {
	d       *Discoverer
	ctx     context.Context
	request Request
	realm   string
	queries int
}
type lookupResult struct {
	records []Record
	expires time.Time
	names   []string
}

func (s *search) query(name string, typ RRType) (Answer, error) {
	if err := s.ctx.Err(); err != nil {
		return Answer{}, err
	}
	if s.queries >= s.d.cfg.MaxQueries {
		return Answer{}, ErrLimit
	}
	s.queries++
	a, err := s.d.cfg.Resolver.Lookup(s.ctx, name, typ)
	if err != nil {
		return Answer{}, errors.Join(ErrDNS, err)
	}
	if err := s.ctx.Err(); err != nil {
		return Answer{}, err
	}
	if a.RCode != RCodeSuccess && a.RCode != RCodeNameError {
		return Answer{}, fmt.Errorf("%w: response code %d", ErrDNS, a.RCode)
	}
	if s.request.RequireAuthenticated && !a.Authenticated {
		return Answer{}, ErrUnauthorized
	}
	if len(a.Records) > 1024 {
		return Answer{}, ErrLimit
	}
	if len(a.Records) > 0 && (a.ReceivedAt.IsZero() || a.ReceivedAt.After(s.d.cfg.Now())) {
		return Answer{}, fmt.Errorf("%w: missing receipt time", ErrInvalid)
	}
	return a, nil
}
func (s *search) lookup(name string, typ RRType, noAlias bool) (lookupResult, error) {
	name, err := absolute(name, true)
	if err != nil {
		return lookupResult{}, err
	}
	result := lookupResult{}
	seen := make(map[string]bool)
	for len(seen) < s.d.cfg.MaxDepth {
		if seen[name] {
			return lookupResult{}, ErrLimit
		}
		seen[name] = true
		result.names = appendNames(result.names, name)
		a, err := s.query(name, typ)
		if err != nil {
			return lookupResult{}, err
		}
		var cn *Record
		for _, r := range a.Records {
			owner, err := absolute(r.Name, true)
			if err != nil {
				return lookupResult{}, err
			}
			if owner != name {
				continue
			}
			switch r.Type {
			case TypeCNAME:
				if noAlias {
					return lookupResult{}, fmt.Errorf("%w: SRV target is an alias", ErrInvalid)
				}
				if cn != nil {
					return lookupResult{}, fmt.Errorf("%w: multiple CNAMEs", ErrInvalid)
				}
				copyRecord := r
				cn = &copyRecord
				result.expires = earlier(result.expires, ttlDeadline(a.ReceivedAt, r.TTL))
			case typ:
				result.records = append(result.records, r)
				result.expires = earlier(result.expires, ttlDeadline(a.ReceivedAt, r.TTL))
			}
		}
		if cn != nil && len(result.records) > 0 {
			return lookupResult{}, fmt.Errorf("%w: CNAME coexists with data", ErrInvalid)
		}
		var alias string
		if cn != nil {
			alias, err = absolute(cn.CNAME, true)
			if err != nil {
				return lookupResult{}, err
			}
			if !s.permitted(alias) {
				return lookupResult{}, ErrUnauthorized
			}
			result.names = appendNames(result.names, alias)
		}
		if a.RCode == RCodeNameError || len(result.records) > 0 || cn == nil {
			if len(result.records) == 0 {
				result.expires = earlier(result.expires, a.NegativeExpiresAt)
			}
			if a.RCode == RCodeNameError && len(result.records) > 0 {
				return lookupResult{}, ErrInvalid
			}
			return result, nil
		}
		name = alias
	}
	return lookupResult{}, ErrLimit
}

type service struct {
	extended  bool
	app       uint32
	protocols []Transport
	diameter  bool
}

func parseService(text string) (service, error) {
	if len(text) > 255 {
		return service{}, ErrInvalid
	}
	fields := strings.Split(strings.ToLower(text), ":")
	parsed := service{}
	if fields[0] == "aaa" {
		parsed.diameter = true
	} else if strings.HasPrefix(fields[0], "aaa+ap") {
		id := strings.TrimPrefix(fields[0], "aaa+ap")
		if id == "" || len(id) > 10 || len(id) > 1 && id[0] == '0' {
			return service{}, ErrInvalid
		}
		for _, c := range []byte(id) {
			if c < '0' || c > '9' {
				return service{}, ErrInvalid
			}
		}
		value, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return service{}, ErrInvalid
		}
		parsed = service{diameter: true, extended: true, app: uint32(value)}
	} else {
		return parsed, nil
	}
	for _, tag := range fields[1:] {
		// RFC 3958 §6.5 Verified Erratum 2106; RFC 6408 §3.
		if len(tag) == 0 || len(tag) > 32 || tag[0] < 'a' || tag[0] > 'z' {
			return service{}, ErrInvalid
		}
		for _, c := range []byte(tag) {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.' {
				continue
			}
			return service{}, ErrInvalid
		}
		parsed.protocols = append(parsed.protocols, Transport(tag))
	}
	return parsed, nil
}
func (s *search) permitted(name string) bool {
	n := identityName(name)
	realm := identityName(s.realm)
	return n == realm || strings.HasSuffix(n, "."+realm) || s.d.cfg.AllowDelegation != nil && s.d.cfg.AllowDelegation(realm, n)
}
func (s *search) walk(name string, data lookupResult, transport Transport, expiry time.Time, names []string, path map[string]bool, depth int) ([]Candidate, error) {
	if depth >= s.d.cfg.MaxDepth || path[name] {
		return nil, ErrLimit
	}
	path[name] = true
	defer delete(path, name)
	records := slices.Clone(data.records)
	slices.SortStableFunc(records, func(a, b Record) int {
		if a.NAPTR == nil || b.NAPTR == nil {
			return 0
		}
		if a.NAPTR.Order != b.NAPTR.Order {
			return int(a.NAPTR.Order) - int(b.NAPTR.Order)
		}
		return int(a.NAPTR.Preference) - int(b.NAPTR.Preference)
	})
	parsed := make([]service, len(records))
	extended := false
	for i, r := range records {
		if r.NAPTR == nil {
			return nil, ErrInvalid
		}
		service, err := parseService(r.NAPTR.Service)
		if err != nil {
			return nil, err
		}
		parsed[i] = service
		extended = extended || service.extended
	}
	var result []Candidate
	var failures []error
	for i, r := range records {
		service := parsed[i]
		n := r.NAPTR
		if !service.diameter || extended && !service.extended || service.extended && service.app != s.request.ApplicationID {
			continue
		}
		if len(service.protocols) > 0 && !slices.Contains(service.protocols, transport) {
			continue
		}
		if n.Regexp != "" {
			failures = append(failures, ErrInvalid)
			continue
		}
		flag := strings.ToLower(n.Flags)
		if flag != "" && flag != "s" && flag != "a" {
			continue
		}
		target, err := absolute(n.Replacement, flag != "a")
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !s.permitted(target) {
			failures = append(failures, ErrUnauthorized)
			continue
		}
		nextNames := appendNames(names, target)
		var candidates []Candidate
		switch flag {
		case "s":
			candidates, err = s.resolveSRV(target, transport, expiry, nextNames, *n)
		case "a":
			candidates, err = s.resolveHost(target, transport, defaultPort(transport), expiry, nextNames, *n, SRV{}, false)
		default:
			var next lookupResult
			next, err = s.lookup(target, TypeNAPTR, false)
			if err == nil {
				candidates, err = s.walk(target, next, transport, earlier(expiry, next.expires), appendNames(nextNames, next.names...), path, depth+1)
			}
		}
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		if err != nil {
			failures = append(failures, err)
		}
		result = append(result, candidates...)
		if len(result) > s.d.cfg.MaxCandidates {
			return nil, ErrLimit
		}
	}
	if len(result) == 0 {
		return nil, errors.Join(append([]error{ErrNoService}, failures...)...)
	}
	return result, nil
}
func defaultPort(transport Transport) uint16 {
	if transport == TLS || transport == DTLS {
		return 5868
	}
	return 3868
}
func (s *search) resolveSRV(name string, transport Transport, expiry time.Time, names []string, n NAPTR) ([]Candidate, error) {
	data, err := s.lookup(name, TypeSRV, false)
	if err != nil {
		return nil, err
	}
	if len(data.records) == 0 {
		return nil, ErrNoService
	}
	expiry = earlier(expiry, data.expires)
	names = appendNames(names, data.names...)
	ordered, err := s.orderSRV(data.records)
	if err != nil {
		return nil, err
	}
	var result []Candidate
	var failures []error
	for _, r := range ordered {
		if r.SRV == nil {
			return nil, ErrInvalid
		}
		v := r.SRV
		if v.Target == "." {
			return nil, ErrNoService
		}
		target, err := absolute(v.Target, false)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !s.permitted(target) {
			failures = append(failures, ErrUnauthorized)
			continue
		}
		candidates, err := s.resolveHost(target, transport, v.Port, expiry, appendNames(names, target), n, *v, true)
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		if err != nil {
			failures = append(failures, err)
		}
		result = append(result, candidates...)
		if len(result) > s.d.cfg.MaxCandidates {
			return nil, ErrLimit
		}
	}
	if len(result) == 0 {
		return nil, errors.Join(append([]error{ErrNoService}, failures...)...)
	}
	return result, nil
}
func (s *search) orderSRV(records []Record) ([]Record, error) {
	records = slices.Clone(records)
	for _, r := range records {
		if r.SRV == nil {
			return nil, ErrInvalid
		}
	}
	slices.SortStableFunc(records, func(a, b Record) int { return int(a.SRV.Priority) - int(b.SRV.Priority) })
	ordered := make([]Record, 0, len(records))
	for len(records) > 0 {
		end := 1
		for end < len(records) && records[end].SRV.Priority == records[0].SRV.Priority {
			end++
		}
		group := slices.Clone(records[:end])
		records = records[end:]
		for len(group) > 0 {
			slices.SortStableFunc(group, func(a, b Record) int {
				if a.SRV.Weight == 0 && b.SRV.Weight != 0 {
					return -1
				}
				if b.SRV.Weight == 0 && a.SRV.Weight != 0 {
					return 1
				}
				return 0
			})
			total := 0
			for _, r := range group {
				total += int(r.SRV.Weight)
			}
			// RFC 2782 Weight: the draw includes both zero and total.
			s.d.randomMu.Lock()
			draw := s.d.cfg.RandIntn(total + 1)
			s.d.randomMu.Unlock()
			if draw < 0 || draw > total {
				return nil, ErrInvalid
			}
			index := 0
			sum := 0
			for i, r := range group {
				sum += int(r.SRV.Weight)
				if sum >= draw {
					index = i
					break
				}
			}
			ordered = append(ordered, group[index])
			group = slices.Delete(group, index, index+1)
		}
	}
	return ordered, nil
}
func (s *search) resolveHost(host string, transport Transport, port uint16, expiry time.Time, names []string, n NAPTR, srv SRV, noAlias bool) ([]Candidate, error) {
	var addresses []netip.Addr
	var failures []error
	for _, typ := range []RRType{TypeA, TypeAAAA} {
		data, err := s.lookup(host, typ, noAlias)
		if err != nil {
			if errors.Is(err, ErrInvalid) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrLimit) {
				return nil, err
			}
			failures = append(failures, err)
			continue
		}
		if len(data.records) == 0 {
			continue
		}
		expiry = earlier(expiry, data.expires)
		names = appendNames(names, data.names...)
		for _, r := range data.records {
			if !r.Address.IsValid() || typ == TypeA && !r.Address.Is4() || typ == TypeAAAA && !r.Address.Is6() {
				return nil, ErrInvalid
			}
			if !slices.Contains(addresses, r.Address) {
				addresses = append(addresses, r.Address)
			}
		}
	}
	if len(addresses) == 0 {
		return nil, errors.Join(append([]error{ErrNoService}, failures...)...)
	}
	if expiry.IsZero() {
		return nil, ErrInvalid
	}
	ttl := expiry.Sub(s.d.cfg.Now())
	if ttl < 0 {
		ttl = 0
	}
	return []Candidate{{Realm: s.request.Realm, ApplicationID: s.request.ApplicationID, Transport: transport, Host: identityName(host), Port: port, Addresses: addresses, Names: names, Order: n.Order, Preference: n.Preference, Priority: srv.Priority, Weight: srv.Weight, TTL: ttl, ExpiresAt: expiry}}, nil
}
