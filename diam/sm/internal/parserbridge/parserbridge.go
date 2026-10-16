// Package parserbridge gives package sm the smparser conversions that are not
// part of smparser's public API. smparser installs each one during its
// initialization; this package cannot import smparser, so each is held as any
// with its concrete function type documented beside it.
package parserbridge

// FromValidatedCER is a func(*base.CER, []uint32) *smparser.CER. It copies a
// CER the protocol core already validated, with the parser's application list,
// without repeating the RFC 6733 §5.3 negotiation.
var FromValidatedCER any

// FromValidatedCEA is a func(*base.CEA, []uint32, error) (*smparser.CEA, error).
// It copies a core handshake result and translates its parser error without
// repeating RFC 6733 §5.3.2 validation.
var FromValidatedCEA any
