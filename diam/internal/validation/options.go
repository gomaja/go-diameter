// Package validation carries private options between Diameter's validator and
// its internal error-answer builder without exposing a public validation bypass.
package validation

// ErrorAnswer is an internal capability; its zero value keeps all checks.
type ErrorAnswer struct{ missingSessionID bool }

// WithoutSessionID is used only when the request's first top-level Session-Id
// was absent or undecodable (RFC 6733 §6.2).
func WithoutSessionID() ErrorAnswer { return ErrorAnswer{missingSessionID: true} }

// MissingSessionID reports the sole presence exception authorized by the builder.
func (o ErrorAnswer) MissingSessionID() bool { return o.missingSessionID }
