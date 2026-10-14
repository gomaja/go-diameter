package dnsdiam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type clientExpiryKey struct{}

// tlsEvidence keeps callback selection evidence with the configuration that
// produced it. Its owner may retain it only for compatible discovery proofs.
// Each admitted connection also stores its deadline in its own context.
type tlsEvidence struct {
	config               *tls.Config
	selectedClientExpiry atomic.Pointer[time.Time]
}

// prepare keeps DNS policy outside peer.Manager. The same validator applies to
// both CER and CEA admission (RFC 6733 §§5.2, 13.1–13.2).
func (p Policy) prepare(c Candidate, now func() time.Time) (peer.Discovery, error) {
	spec, _, err := p.prepareWithEvidence(c, now, nil)
	return spec, err
}

func (p Policy) prepareWithEvidence(c Candidate, now func() time.Time, retained *tlsEvidence) (peer.Discovery, *tlsEvidence, error) {
	if now == nil || p.Authorize == nil || c.Host == "" || c.Realm == "" || len(c.Addresses) == 0 || c.ExpiresAt.IsZero() {
		return peer.Discovery{}, nil, fmt.Errorf("%w: candidate, clock and role policy required", ErrInvalid)
	}
	c.Addresses = append(c.Addresses[:0:0], c.Addresses...)
	c.Names = append(c.Names[:0:0], c.Names...)
	var config *tls.Config
	var evidence *tlsEvidence
	network := "tcp"
	switch c.Transport {
	case TLS:
		if p.TLSConfig == nil || p.TLSConfig.InsecureSkipVerify || (len(p.TLSConfig.Certificates) == 0 && p.TLSConfig.GetClientCertificate == nil) {
			return peer.Discovery{}, nil, fmt.Errorf("%w: verified TLS and client credentials required", ErrUnauthorized)
		}
		evidence = retained
		if evidence == nil {
			evidence = &tlsEvidence{config: p.TLSConfig.Clone()}
			config = evidence.config
			config.ServerName = c.Host
			config.Time = now
			if config.MinVersion < tls.VersionTLS12 {
				config.MinVersion = tls.VersionTLS12
			}
			prior := config.VerifyConnection
			config.VerifyConnection = func(state tls.ConnectionState) error {
				if _, err := certificateDeadline(state, c, now()); err != nil {
					return err
				}
				if prior != nil {
					return prior(state)
				}
				return nil
			}
			if get := config.GetClientCertificate; get != nil {
				config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					cert, err := get(info)
					if err != nil {
						return nil, err
					}
					if cert == nil || len(cert.Certificate) == 0 {
						return nil, fmt.Errorf("%w: client certificate required", ErrUnauthorized)
					}
					deadline, err := localCertificateDeadline(*cert, now())
					if err != nil {
						return nil, err
					}
					for {
						old := evidence.selectedClientExpiry.Load()
						if old != nil && !deadline.Before(*old) {
							break
						}
						if evidence.selectedClientExpiry.CompareAndSwap(old, &deadline) {
							break
						}
					}
					return cert, nil
				}
			}
		}
		config = evidence.config
	case TCP, SCTP:
		if !p.AllowPlaintext {
			return peer.Discovery{}, nil, fmt.Errorf("%w: plaintext requires explicit external security policy", ErrUnauthorized)
		}
		if c.Transport == SCTP {
			network = "sctp"
		}
	default:
		return peer.Discovery{}, nil, ErrUnsupportedTransport
	}
	spec := peer.Discovery{Peer: peer.PeerConfig{Host: datatype.DiameterIdentity(c.Host)}, Realm: datatype.DiameterIdentity(c.Realm), ApplicationIDs: []uint32{c.ApplicationID}, ExpiresAt: c.ExpiresAt}
	if p.AllowRealm != nil {
		spec.AllowRealm = func(expected, actual datatype.DiameterIdentity) bool {
			return p.AllowRealm(identityName(string(expected)), identityName(string(actual)))
		}
	}
	for _, ip := range c.Addresses {
		if !ip.IsValid() || ip.Zone() != "" {
			return peer.Discovery{}, nil, fmt.Errorf("%w: invalid address", ErrInvalid)
		}
		spec.Peer.Endpoints = append(spec.Peer.Endpoints, peer.Endpoint{Network: network, Address: net.JoinHostPort(ip.String(), strconv.Itoa(int(c.Port))), TLSConfig: config})
	}
	spec.Validate = func(conn diam.Conn, meta *smpeer.Metadata) (time.Time, error) {
		if conn == nil || meta == nil || conn.Closed() {
			return time.Time{}, fmt.Errorf("%w: connection or metadata unavailable", ErrUnauthorized)
		}
		actualHost, hostErr := absolute(string(meta.OriginHost), false)
		actualRealmName, realmErr := absolute(string(meta.OriginRealm), false)
		if hostErr != nil || realmErr != nil || identityName(actualHost) != identityName(c.Host) {
			return time.Time{}, fmt.Errorf("%w: Origin-Host mismatch", ErrUnauthorized)
		}
		actualRealm := identityName(actualRealmName)
		if actualRealm != identityName(c.Realm) && (p.AllowRealm == nil || !p.AllowRealm(c.Realm, actualRealm)) {
			return time.Time{}, fmt.Errorf("%w: Origin-Realm mismatch", ErrUnauthorized)
		}
		supported := c.ApplicationID == 0
		for _, app := range meta.Applications {
			if app == c.ApplicationID || app == ^uint32(0) {
				supported = true
			}
		}
		if !supported {
			return time.Time{}, fmt.Errorf("%w: application mismatch", ErrUnauthorized)
		}
		expires := c.ExpiresAt
		if c.Transport == TLS {
			state := conn.TLS()
			if state == nil || !state.HandshakeComplete {
				return time.Time{}, fmt.Errorf("%w: TLS required", ErrUnauthorized)
			}
			capAt, err := certificateDeadline(*state, c, now())
			if err != nil {
				return time.Time{}, err
			}
			expires = earlier(expires, capAt)
			for _, cert := range config.Certificates {
				localAt, err := localCertificateDeadline(cert, now())
				if err != nil {
					return time.Time{}, err
				}
				expires = earlier(expires, localAt)
			}
			connectionContext := conn.Context()
			if connectionContext == nil {
				connectionContext = context.Background()
			}
			localAt, _ := connectionContext.Value(clientExpiryKey{}).(time.Time)
			if selected := evidence.selectedClientExpiry.Load(); selected != nil {
				localAt = earlier(localAt, *selected)
			}
			if config.GetClientCertificate != nil && localAt.IsZero() {
				return time.Time{}, fmt.Errorf("%w: client certificate was not requested", ErrUnauthorized)
			}
			if !localAt.IsZero() {
				expires = earlier(expires, localAt)
				conn.SetContext(context.WithValue(connectionContext, clientExpiryKey{}, localAt))
			}
		}
		if conn.Closed() {
			return time.Time{}, fmt.Errorf("%w: connection closed during authorization", ErrUnauthorized)
		}
		if !now().Before(expires) {
			return time.Time{}, ErrExpired
		}
		proof := c
		proof.Names = append([]string(nil), c.Names...)
		proof.Addresses = append(c.Addresses[:0:0], c.Addresses...)
		if err := p.Authorize(proof, conn, meta.Clone()); err != nil {
			return time.Time{}, fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		if conn.Closed() {
			return time.Time{}, fmt.Errorf("%w: connection closed during authorization", ErrUnauthorized)
		}
		if !now().Before(expires) {
			return time.Time{}, ErrExpired
		}
		return expires, nil
	}
	return spec, evidence, nil
}

func localCertificateDeadline(cert tls.Certificate, now time.Time) (time.Time, error) {
	var expires time.Time
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return time.Time{}, fmt.Errorf("%w: client credential missing", ErrUnauthorized)
	}
	for _, raw := range cert.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil || now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) {
			return time.Time{}, fmt.Errorf("%w: expired or invalid client certificate", ErrUnauthorized)
		}
		expires = earlier(expires, parsed.NotAfter)
	}
	return expires, nil
}

// RFC 6733 §5.2: a site certificate must cover the NAPTR owner/replacement and
// SRV owner/target, as well as the identity authenticated on the connection.
func certificateDeadline(state tls.ConnectionState, c Candidate, now time.Time) (time.Time, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return time.Time{}, fmt.Errorf("%w: certificate chain unverified", ErrUnauthorized)
	}
	leaf := state.PeerCertificates[0]
	for _, name := range append(append([]string(nil), c.Names...), c.Host) {
		if err := leaf.VerifyHostname(identityName(name)); err != nil {
			return time.Time{}, fmt.Errorf("%w: discovery certificate name %s: %w", ErrUnauthorized, name, err)
		}
	}
	var expires time.Time
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				return time.Time{}, fmt.Errorf("%w: certificate expired", ErrUnauthorized)
			}
			expires = earlier(expires, cert.NotAfter)
		}
	}
	return expires, nil
}
