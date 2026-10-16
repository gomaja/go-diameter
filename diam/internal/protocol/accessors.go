package protocol

// Phase returns the current phase within the caller's serialization domain.
func (c *Core) Phase() Phase { return c.phase }

// Ready reports whether admission callbacks have completed within the caller's
// serialization domain.
func (c *Core) Ready() bool { return c.ready }
