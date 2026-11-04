//go:build linux && !386

package sm

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-sctp"
)

func TestAcceptedRequestHandlerSCTPDPR(t *testing.T) {
	requireSCTP(t)
	d := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := *cloneTestSettings(serverSettings2, d)
	cfg.DPRCloseTimeout = time.Hour
	notices := make(chan DisconnectCause, 1)
	cfg.OnDPR = func(_ diam.Conn, cause DisconnectCause) { notices <- cause }
	events := make(chan diam.ProtocolErrorEvent, 1)
	cfg.OnProtocolError = func(event diam.ProtocolErrorEvent) { events <- event }
	machine := mustNewStateMachine(t, &cfg, d)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	writes := make(chan error, 1)
	machine.Handle("RAR", diam.HandlerFunc(func(c diam.Conn, request *diam.Message) {
		close(started)
		<-release
		answer := request.Answer(diam.Success)
		answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost))
		answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm))
		_, err := answer.WriteTo(c)
		writes <- err
	}))
	server := diamtest.NewUnstartedServerNetwork("sctp", machine, d)
	server.Config.MaxConcurrentHandlers = 2
	server.Start()
	defer server.Close()
	address, err := sctp.ResolveAddr("sctp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wire, err := sctp.Dial(ctx, "sctp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wire.Close() }()
	if err := wire.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := regressionCER(t, d, 1001).WriteTo(wire); err != nil {
		t.Fatal(err)
	}
	cea, err := diam.ReadMessage(wire, d)
	if err != nil || !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA=%v error=%v", cea, err)
	}
	request := diam.NewMessage(diam.ReAuth, diam.RequestFlag|diam.ProxiableFlag, 0, 0x15601, 0x15602, d)
	for _, field := range []struct {
		code uint32
		data datatype.Type
	}{
		{avp.SessionID, datatype.UTF8String("synthetic.example;156")},
		{avp.OriginHost, clientSettings.OriginHost},
		{avp.OriginRealm, clientSettings.OriginRealm},
		{avp.DestinationRealm, cfg.OriginRealm},
		{avp.AuthApplicationID, datatype.Unsigned32(1002)},
		{avp.ReAuthRequestType, datatype.Enumerated(0)},
	} {
		request.AddAVP(diam.NewAVP(field.code, avp.Mbit, 0, field.data))
	}
	if _, err := request.WriteTo(wire); err != nil {
		t.Fatal(err)
	}
	protocolGenerationAwait(t, started)
	dpr := acceptedDPR(t)
	dpr.Header.HopByHopID, dpr.Header.EndToEndID = 0x15603, 0x15604
	if _, err := dpr.WriteTo(wire); err != nil {
		t.Fatal(err)
	}
	// RFC 6733 §5.4: an admitted request handler counts as work in flight.
	dpa, err := diam.ReadMessage(wire, d)
	if err != nil || dpa.Header.CommandCode != diam.DisconnectPeer || dpa.Header.CommandFlags != 0 || dpa.Header.ApplicationID != 0 || dpa.Header.HopByHopID != dpr.Header.HopByHopID || dpa.Header.EndToEndID != dpr.Header.EndToEndID || !testResultCode(dpa, diam.UnableToComply) {
		t.Fatalf("DPA=%v error=%v; want correlated 5012", dpa, err)
	}
	if cause := protocolGenerationAwait(t, notices); cause != DisconnectRebooting {
		t.Fatalf("OnDPR cause=%v", cause)
	}
	unblock()
	answer, err := diam.ReadMessage(wire, d)
	if err != nil {
		t.Fatal(err)
	}
	want := request.Answer(diam.Success)
	want.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost))
	want.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm))
	gotBytes, err := answer.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := want.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("handler answer=%x; want=%x", gotBytes, wantBytes)
	}
	if err := protocolGenerationAwait(t, writes); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatalf("unexpected protocol event: %+v", event)
	default:
	}
}
