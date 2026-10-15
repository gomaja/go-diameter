//go:build linux && !386

package sm

import (
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestProtocolErrorInvalidDWRSCTPStream(t *testing.T) {
	testDict := newSMTestDictionary(creditcontrol.Dictionary())
	serverSettings2 :=

		cloneTestSettings(serverSettings2, testDict)

	requireSCTP(t)
	events := make(chan diam.ProtocolErrorEvent, 4)
	handshakes := make(chan diam.Conn, 1)
	cfg := *serverSettings2
	cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { handshakes <- c }
	logs := logtest.New()
	server := diamtest.NewUnstartedServerNetwork("sctp", mustNewStateMachine(t, &cfg, testDict), testDict)
	server.Config.Logger = logs.Logger()
	server.Start()
	defer server.Close()
	answers := make(chan *diam.Message, 4)
	mux := diam.NewServeMux()
	mux.HandleFunc("ALL", func(_ diam.Conn, m *diam.Message) { answers <- m })
	peer, err := diam.DialNetworkTimeout("sctp", server.Addr, mux, testDict, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err = acceptedRestartCER(t, "stream.example", 1001, 111).WriteTo(peer); err != nil {
		t.Fatal(err)
	}
	cea := protocolGenerationAwait(t, answers)
	if cea.Header.CommandCode != diam.CapabilitiesExchange || !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA = %v", cea)
	}
	c := protocolGenerationAwait(t, handshakes)
	const stream = 7
	invalid := protocolGenerationInvalidDWR(t, 0x86700007)
	invalid.AVP[0].Data = datatype.DiameterIdentity("stream.example")
	wire, err := invalid.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = peer.WriteStream(wire, stream); err != nil {
		t.Fatal(err)
	}
	header := *invalid.Header
	header.MessageLength = uint32(len(wire))
	event := protocolGenerationAwait(t, events)
	assertProtocolGenerationDWR(t, event, c, header, stream)
	valid := regressionDWR(t)
	setWireIdentity(t, valid, avp.OriginHost, "stream.example")
	valid.Header.HopByHopID, valid.Header.EndToEndID = 0x86700008, 0x86700009
	if _, err = valid.WriteToStream(peer, stream); err != nil {
		t.Fatal(err)
	}
	dwa := protocolGenerationAwait(t, answers)
	if dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.HopByHopID != valid.Header.HopByHopID || dwa.MessageStream() != stream || !testResultCode(dwa, diam.Success) {
		t.Fatalf("DWA = %v stream %d", dwa, dwa.MessageStream())
	}
	if c.Closed() {
		t.Fatal("invalid DWR closed SCTP connection")
	}
	select {
	case extra := <-events:
		t.Fatalf("extra notification = %+v", extra)
	default:
	}
	records := logs.Records()
	if len(records) != 1 || records[0].Message != "sm: invalid DWR" || records[0].Level != slog.LevelWarn {
		t.Fatalf("logs = %v", records)
	}
	t.Logf("invalid DWR hop=0x%x end=0x%x stream=%d callback_stream=%d reply=%d closing=%v; valid DWA hop=0x%x stream=%d", header.HopByHopID, header.EndToEndID, stream, event.Message.Stream, event.Reply, event.Closing, dwa.Header.HopByHopID, dwa.MessageStream())
}
