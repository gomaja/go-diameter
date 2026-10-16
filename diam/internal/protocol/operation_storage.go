package protocol

// recycleOperation retains at most one completed record per connection. An
// outstanding writer keeps its own record until its terminal result, even when
// its answer has already been consumed.
func (c *Core) recycleOperation(op *operation) {
	*op = operation{}
	if c.spareOperation == nil {
		c.spareOperation = op
	}
}
