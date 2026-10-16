// Package transport shares native connection lifecycle signals inside diam.
package transport

// Signal exposes a read signal through an unexported method. Embedding it does
// not add an exported method to the handler-visible connection.
type Signal func() <-chan struct{}

func (s Signal) readDone() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s()
}

// ReadDone discovers the native read signal at this connection layer. Wrappers
// decide which capabilities they intercept before unwrapping to another layer.
func ReadDone(c any) (<-chan struct{}, bool) {
	n, ok := c.(interface{ readDone() <-chan struct{} })
	if !ok {
		return nil, false
	}
	done := n.readDone()
	return done, done != nil
}
