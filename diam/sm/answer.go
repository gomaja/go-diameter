package sm

import (
	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// answerCorrelation belongs to one request on one connection generation.
// RFC 6733 §§3, 6.2.1 require answer identifiers to preserve the request's IDs;
// checking both on receipt also prevents cross-request and stale answer credit.
type answerCorrelation struct {
	conn       diam.Conn
	generation uint64
	command    uint32
	hop, end   uint32
}

func correlateAnswer(c diam.Conn, m *diam.Message) *answerCorrelation {
	return &answerCorrelation{c, connectionGeneration(c), m.Header.CommandCode, m.Header.HopByHopID, m.Header.EndToEndID}
}

func connectionGeneration(c diam.Conn) uint64 {
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok {
		return lifecycle.Generation()
	}
	return 0
}

func (r *answerCorrelation) matches(c diam.Conn, m *diam.Message) bool {
	if r == nil || c != r.conn || c.Closed() || connectionGeneration(c) != r.generation {
		return false
	}
	if lifecycle, ok := diam.ConnAs[diam.ConnLifecycle](c); ok && lifecycle.RetirementReason() != 0 {
		return false
	}
	return m.Header.ApplicationID == 0 && m.Header.CommandFlags&diam.RequestFlag == 0 &&
		m.Header.CommandCode == r.command && m.Header.HopByHopID == r.hop && m.Header.EndToEndID == r.end
}

// RFC 6733 §6.3: Origin-Host identifies the sender. Binding it to the admitted
// direct peer is policy shared with Manager; DiameterIdentity ignores case.
func boundHost(c diam.Conn, host datatype.DiameterIdentity) bool {
	ctx := c.Context()
	if ctx == nil {
		return false
	}
	meta, ok := smpeer.FromContext(ctx)
	return ok && meta != nil && len(host) != 0 && equalIdentity(host, meta.OriginHost)
}

func equalIdentity(a, b datatype.DiameterIdentity) bool {
	// RFC 6733 §§4.3, 5.6.4: DiameterIdentity comparison folds ASCII
	// A-Z only, as Manager does; Unicode lookalikes are different hosts.
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func messageBoundHost(c diam.Conn, m *diam.Message) bool {
	a, err := m.FindAVP(avp.OriginHost, 0)
	if err != nil {
		return false
	}
	host, ok := a.Data.(datatype.DiameterIdentity)
	return ok && boundHost(c, host)
}
