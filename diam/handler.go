package diam

// HandlerAs returns the first handler in h's chain that implements T. It visits
// h and then successive Unwrap() Handler results, until nil or a handler without
// Unwrap. A chain must terminate. When no handler implements T it returns the
// zero T and false. A wrapper implementing T intercepts it and can delegate by
// calling HandlerAs on its wrapped handler.
func HandlerAs[T any](h Handler) (T, bool) {
	for h != nil {
		if v, ok := h.(T); ok {
			return v, true
		}
		u, ok := h.(interface{ Unwrap() Handler })
		if !ok {
			break
		}
		h = u.Unwrap()
	}
	var zero T
	return zero, false
}
