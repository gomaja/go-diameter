package sm

import "github.com/gomaja/go-diameter/diam/internal/protocol"

func (s *acceptedHandshake) phase() protocol.Phase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Phase()
}

func (s *acceptedHandshake) readyOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Phase() == protocol.Open && s.core.Ready()
}
