package sm

import (
	"errors"
	"fmt"
	"io"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

// Synthetic peers and builder tests use shared base construction directly.
// Product receive, rejection, hook and Closing decisions all live in Core.
func buildTestCEA(sm *StateMachine, c diam.Conn, m *diam.Message) (*diam.Message, error) {
	cfg := sm.capabilities(c, m)
	if len(cfg.HostIPAddresses) == 0 {
		var err error
		cfg.HostIPAddresses, err = getLocalAddresses(c)
		if err != nil {
			return nil, err
		}
	}
	return base.BuildCEA(m, cfg, diam.Success)
}
func sendTestCEA(sm *StateMachine, c diam.Conn, m *diam.Message, cause error) error {
	cfg := baseSettings(sm.cfg)
	if len(cfg.HostIPAddresses) == 0 {
		var err error
		cfg.HostIPAddresses, err = getLocalAddresses(c)
		if err != nil {
			return fmt.Errorf("error CEA '%w' create failure: %w", cause, err)
		}
	}
	code := uint32(diam.UnableToComply)
	if errors.Is(cause, smparser.ErrNoCommonApplication) {
		code = diam.NoCommonApplication
	}
	if errors.Is(cause, smparser.ErrNoCommonSecurity) {
		code = diam.NoCommonSecurity
	}
	m, err := base.BuildCEA(m, cfg, code)
	if err == nil {
		err = writeTestReply(c, m)
	}
	if err != nil {
		return fmt.Errorf("error CEA '%w' send failure: %w", cause, err)
	}
	return nil
}
func (sm *StateMachine) sendTestErrorAnswer(c diam.Conn, m *diam.Message, code uint32, failed []*diam.AVP, protocolError bool) (uint32, error) {
	cfg := baseSettings(sm.cfg)
	cfg.ResolveHostIPAddresses = func() ([]datatype.Address, error) { return getLocalAddresses(c) }
	a, err := base.BuildErrorAnswer(m, cfg, code, failed, protocolError)
	if err != nil {
		return code, err
	}
	return code, writeTestReply(c, a)
}
func writeTestReply(c diam.Conn, m *diam.Message) error {
	n, err := m.WriteTo(c)
	if err == nil && n != int64(m.Len()) {
		err = io.ErrShortWrite
	}
	return err
}
func validateDPR(m *diam.Message) (DisconnectCause, error) {
	v, err := base.ValidateDPR(m)
	return DisconnectCause(v), err
}
