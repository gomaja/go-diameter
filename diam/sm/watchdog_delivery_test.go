package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestDisabledClientWatchdogDoesNotRetainReceipts(t *testing.T) {
	p := newProtocolClientWire(t, nil)
	p.send(t, protocolClientCEA(p.cer, diam.Success))
	if result := p.dialResult(t); result.err != nil {
		t.Fatal(result.err)
	}
	state := p.client.Handler.acceptedCore(p.conn, nil, false)
	before := state.snapshot().Timer(protocol.WatchdogTimer)
	// Finish each real dispatch before inspecting retained receive storage.
	dispatched := make(chan struct{}, 1)
	p.client.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched <- struct{}{} }))
	for range 16 {
		p.send(t, diam.NewRequest(999, 4, p.conn.Dictionary()).Answer(diam.Success))
		<-dispatched
		p.send(t, acceptedDWA(t, regressionDWR(t), diam.Success))
		<-dispatched
	}
	if after := state.snapshot().Timer(protocol.WatchdogTimer); after != before || after.Token != 0 {
		t.Fatalf("disabled watchdog retained a receive timer: before=%+v after=%+v", before, after)
	}
}
