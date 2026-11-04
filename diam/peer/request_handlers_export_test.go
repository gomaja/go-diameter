package peer

// RequestHandlersInFlightForTesting counts requests admitted to handlers,
// including requests whose delivery consumers are waiting for a handler slot.
func RequestHandlersInFlightForTesting(m *Manager) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total int64
	for _, s := range m.sessions {
		total += s.handlersInFlight.Load()
	}
	return total
}
