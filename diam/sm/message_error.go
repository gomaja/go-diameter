package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type advertisedAppsKey struct{}

// HandleMessageError implements diam.MessageErrorHandler. RFC 6733 §§7.1-7.2
// reserve E for protocol errors; answers never receive answers. A local answer
// failure is logged here and closes the connection; returning nil means the
// state machine took responsibility. Invalid error descriptions are returned.
func (sm *StateMachine) HandleMessageError(c diam.Conn, request *diam.Message, messageErr *diam.MessageError) error {
	release := request.BeginDispatch()
	defer release()
	if state := sm.acceptedCore(c, request, true); state != nil {
		in := protocol.Input{Kind: protocol.Receive, Message: request, Error: messageErr, ErrorInput: true, TransportClosed: c.Closed()}
		externalAdmission, err := state.validateMessageError(in)
		if err != nil {
			return err
		}
		if externalAdmission && request != nil && request.Header != nil && request.Header.CommandCode == diam.CapabilitiesExchange && len(sm.cfg.HostIPAddresses) == 0 && (messageErr != nil && messageErr.Fatal || base.ValidateHeader(request) != nil) {
			in.RefreshLocalAddresses = true
			in.LocalAddresses, in.Err = getLocalAddresses(c)
		}
		batch := state.prepare(in)
		state.run(batch)
		return nil
	}
	return nil
}

// admittedPeer reports whether a successful CER/CEA stored peer metadata on c.
func admittedPeer(c diam.Conn) bool {
	ctx := c.Context()
	if ctx == nil {
		return false
	}
	_, ok := smpeer.FromContext(ctx)
	return ok
}

func (s *acceptedHandshake) validateMessageError(in protocol.Input) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core.PassiveResponder() {
		s.core.RefreshAdmission(externalPeerClaims(s.conn))
	}
	return s.core.ExternalAdmission(), s.core.ValidateMessageError(in)
}
