package protocol

// CompleteQueuedReply consumes only successful, effect-free answer completion.
// The caller serializes it with Handle, after queue feedback has committed. Any
// result with an outstanding protocol obligation must instead enter Handle.
// Request controls, handshake and terminal replies retain their ordered
// completion effects; ordinary queued answers release only their operation
// record. The transport writer still owns its publication pin.
func (c *Core) CompleteQueuedReply(in Input) bool {
	if in.Connection != c.cfg.Connection || in.Kind != WriteResult || in.Stage != WrittenStage || in.Err != nil {
		return false
	}
	op := c.operations[in.Token]
	if op == nil || !op.queued || !op.reported || op.control != nil || op.closeAfter || op.handshake {
		return false
	}
	expected := in.ExpectedBytes
	if expected == 0 {
		expected = op.length
	}
	if in.Bytes != expected {
		return false
	}
	delete(c.operations, in.Token)
	c.recycleOperation(op)
	return true
}
