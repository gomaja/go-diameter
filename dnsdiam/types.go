package dnsdiam

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RRType identifies the DNS record requested from Resolver.
type RRType uint16

const (
	TypeA     RRType = 1
	TypeCNAME RRType = 5
	TypeAAAA  RRType = 28
	TypeSRV   RRType = 33
	TypeNAPTR RRType = 35
)

// RCode is a DNS response code. Success with no relevant records is NODATA.
type RCode uint16

const (
	RCodeSuccess   RCode = 0
	RCodeNameError RCode = 3
)

// NAPTR contains the fields used by the S-NAPTR application (RFC 3958 §2.2).
type NAPTR struct {
	Order, Preference                   uint16
	Flags, Service, Regexp, Replacement string
}

// SRV contains an advertised endpoint and its selection parameters (RFC 2782).
type SRV struct {
	Priority, Weight, Port uint16
	Target                 string
}

// Record is a package-owned DNS answer. TTL is in seconds; values with the
// high bit set are treated as zero (RFC 2181 §8).
type Record struct {
	Name    string
	Type    RRType
	TTL     uint32
	NAPTR   *NAPTR
	SRV     *SRV
	Address netip.Addr
	CNAME   string
}

// Answer records a single absolute-name query. Authenticated is true only if
// a trusted resolver has validated the data; it does not authorize a peer's
// Diameter role (RFC 6733 §5.2). Receipt time is required for positive records.
type Answer struct {
	Records           []Record
	RCode             RCode
	ReceivedAt        time.Time
	Authenticated     bool
	NegativeExpiresAt time.Time
}

// Resolver provides complete answer records without exposing a DNS client's
// types. Implementations must be safe for concurrent queries and honor ctx.
type Resolver interface {
	Lookup(ctx context.Context, name string, rrtype RRType) (Answer, error)
}

// Transport is an opaque S-NAPTR protocol tag, not a parsed namespace
// (RFC 6408 §3). DTLS means DTLS over SCTP (RFC 6733 §5.2).
type Transport string

const (
	TLS  Transport = "diameter.tls.tcp"
	DTLS Transport = "diameter.dtls"
	TCP  Transport = "diameter.tcp"
	SCTP Transport = "diameter.sctp"
)

// Request describes the service and transports a caller can use. An empty
// transport list permits TLS/TCP only. RequireAuthenticated requires trusted
// DNS validation in addition to transport and role authentication.
type Request struct {
	Realm                string
	ApplicationID        uint32
	Transports           []Transport
	RequireAuthenticated bool
}

// Candidate describes a connection attempt. Host remains a DNS name even when
// the transport dials Addresses. Names preserves all discovery names for site
// certificate validation (RFC 6733 §5.2).
type Candidate struct {
	Realm                               string
	ApplicationID                       uint32
	Transport                           Transport
	Host                                string
	Port                                uint16
	Addresses                           []netip.Addr
	Names                               []string
	Order, Preference, Priority, Weight uint16
	TTL                                 time.Duration
	ExpiresAt                           time.Time
}

// Policy supplies transport credentials and explicit Diameter role authority.
// TLS and authenticated DNS alone do not authorize a Diameter role (RFC 6733
// §5.2). Authorize must be configured for both secure and plaintext peers.
type Policy struct {
	TLSConfig      *tls.Config
	AllowPlaintext bool
	Authorize      func(Candidate, diam.Conn, *smpeer.Metadata) error
	AllowRealm     func(requested, actual string) bool
}

var (
	ErrNoService            = errors.New("dnsdiam: no supported service")
	ErrDNS                  = errors.New("dnsdiam: DNS lookup failed")
	ErrInvalid              = errors.New("dnsdiam: invalid configuration or DNS data")
	ErrLimit                = errors.New("dnsdiam: discovery resource limit exceeded")
	ErrExpired              = errors.New("dnsdiam: discovery expired")
	ErrUnauthorized         = errors.New("dnsdiam: peer not authorized")
	ErrUnsupportedTransport = errors.New("dnsdiam: transport is not supported")
)
