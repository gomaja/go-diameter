package sm

import (
	"io"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type protocolDiscoveryCounter struct {
	diam.Handler
	unwraps atomic.Int32
	served  chan struct{}
}

func (h *protocolDiscoveryCounter) Unwrap() diam.Handler {
	h.unwraps.Add(1)
	return h.Handler
}

func (h *protocolDiscoveryCounter) ServeDIAM(c diam.Conn, m *diam.Message) {
	h.Handler.ServeDIAM(c, m)
	h.served <- struct{}{}
}

func TestProtocolErrorServerNilCallbackValidTraffic(t *testing.T) {
	var wrapper *protocolDiscoveryCounter
	p := newProtocolDeliveryWire(t, 0, true, func(cfg *Settings) { cfg.OnProtocolError = nil }, func(server *diam.Server) {
		wrapper = &protocolDiscoveryCounter{Handler: server.Handler, served: make(chan struct{}, 1)}
		server.Handler = wrapper
	})
	protocolGenerationAwait(t, wrapper.served)
	before := wrapper.unwraps.Load()
	for range 5 {
		p.usable(t)
		protocolGenerationAwait(t, wrapper.served)
	}
	if calls := wrapper.unwraps.Load() - before; calls != 0 {
		t.Fatalf("valid traffic performed %d observer-chain traversals with a nil callback", calls)
	}
}

type protocolDisabledStateMachine struct {
	*StateMachine
	deliveries atomic.Int32
}

func (h *protocolDisabledStateMachine) HandleProtocolError(event diam.ProtocolErrorEvent) {
	h.deliveries.Add(1)
	h.StateMachine.HandleProtocolError(event)
}

func TestProtocolErrorServerNilCallbackMalformedAnswer(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())

	for _, route := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "mux"}[route], func(t *testing.T) {
			var wrapper *protocolDisabledStateMachine
			p := newProtocolDeliveryWire(t, 0, !route, func(cfg *Settings) {
				cfg.OnProtocolError = nil
				cfg.Dict = newTestDictionary(dict.Base(), nasreq.Dictionary())
				cfg.Dict.SetStrict(true)
				cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
			}, func(server *diam.Server) {
				wrapper = &protocolDisabledStateMachine{StateMachine: server.Handler.(*StateMachine)}
				server.Handler = wrapper
				if route {
					mux := diam.NewServeMux()
					mux.Handle("ALL", wrapper)
					server.Handler = mux
				}
			})
			message := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 83, 86, testDict)
			message.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
			p.send(t, message)
			var b [1]byte
			if n, err := p.peer.Read(b[:]); n != 0 || err != io.EOF {
				t.Fatalf("strict malformed answer did not close: n=%d, err=%v", n, err)
			}
			<-p.conn.(interface{ DispatchDone() <-chan struct{} }).DispatchDone()
			if calls := wrapper.deliveries.Load(); calls != 0 {
				t.Fatalf("disabled state-machine observer received %d Server events", calls)
			}
			if logs := p.logs.Records(); len(logs) != 1 || logs[0].Message != "diam: read failed; closing connection" {
				t.Fatalf("decoder logs changed: %v", logs)
			}
		})
	}
}
