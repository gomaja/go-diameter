package sm

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type metadataAcceptHook struct{ *StateMachine }

func (h metadataAcceptHook) HandleAccept(c diam.Conn) func() {
	c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "peer.example", OriginRealm: "example", CEA: &smparser.CEA{}}))
	return h.StateMachine.HandleAccept(c)
}
func TestAcceptMetadataRequiresCER(t *testing.T) {
	d := newSMTestDictionary(creditcontrol.Dictionary())
	sm := mustNewStateMachine(t, testMessageErrorSettings(d), d)
	events := make(chan diam.ProtocolErrorEvent, 2)
	sm.cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	srv := diamtest.NewServer(metadataAcceptHook{sm}, d)
	defer srv.Close()
	peer, e := net.Dial("tcp", srv.Addr)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
	m := regressionDWR(t)
	setWireIdentity(t, m, avp.OriginHost, "peer.example")
	setWireIdentity(t, m, avp.OriginRealm, "example")
	_, _ = m.WriteTo(peer)
	var b [1]byte
	n, e := peer.Read(b[:])
	if n != 0 || e != io.EOF {
		t.Fatalf("accept admission bypassed by metadata: n=%d error=%v", n, e)
	}
	event := protocolEvent(t, events)
	if event.Err.Kind() != diam.ProtocolHandshakeState {
		t.Fatalf("notice=%+v", event)
	}
}
