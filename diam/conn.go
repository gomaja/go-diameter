package diam

// ConnAs returns the first connection in c's chain that implements T. It visits
// c and then successive Unwrap() Conn results, until nil or a connection without
// Unwrap. A chain must terminate. When no connection implements T it returns the
// zero T and false. A wrapper implementing T intercepts it and can delegate by
// calling ConnAs on its wrapped connection.
func ConnAs[T any](c Conn) (T, bool) {
	for c != nil {
		if v, ok := c.(T); ok {
			return v, true
		}
		u, ok := c.(interface{ Unwrap() Conn })
		if !ok {
			break
		}
		c = u.Unwrap()
	}
	var zero T
	return zero, false
}
