// Package dnsdiam discovers Diameter peers through an imported DNS client,
// without adding DNS dependencies to the core go-diameter module.
//
// RFC 6733 §5.2 (updated by RFC 8553 §3.1) supplies realm discovery and lease
// rules. RFC 6408 §§3–5 defines application/transport tags. RFC 3958 §§2.2, 6
// defines S-NAPTR processing; Verified Errata 2106 and 8532 correct its protocol
// grammar and multiple-target wording. RFC 2782 supplies priority/weight ordering
// and forbids aliases in SRV targets. RFC 2181 §§5.2, 8 supplies conservative
// RRset TTL handling, including the zero interpretation of the TTL high bit.
//
// Resolver answers are absolute names without search suffixes. Missing NAPTR
// records permit realm SRV fallback; failed DNS queries do not. TLS/TCP is the
// default. Discovery reports DTLS/SCTP advertisements, but current managed and
// plain-dial integrations reject DTLS. Plaintext requires explicit configuration
// for external security, normally IPsec. Codeberg client types remain private.
//
// Admission verifies site-certificate names along the whole naming chain,
// Origin-Host, realm, application support, and the configured Diameter role
// authority (RFC 6733 §§5.2, 13.1–13.2). Operators supply trust anchors and client
// credentials and configure remote servers to require and verify client
// certificates. Configured credentials alone cannot prove a remote server's
// client-authentication policy. Ordinary Web PKI and DNSSEC alone do not grant
// Diameter authority. Trusted validating resolver configuration is required
// before relying on authenticated DNS; DNSSEC is optional (RFC 3958 §8).
//
// All route/peer lifetimes are capped by the earliest DNS dependency and
// certificate expiry. Zero TTL records can be inspected with Discover but never
// installed as managed leases. Controller.Watch refreshes live leases;
// failed refresh never extends authorization. Plain connections expire and must
// be rediscovered with DialContext. Callbacks and configuration are immutable
// after construction, concurrent where documented, and must return promptly.
package dnsdiam
