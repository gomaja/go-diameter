package sm

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestContextAdmissionClosingClaims(t *testing.T) {
	for _, closing := range []string{"local", "peer"} {
		for _, change := range []string{"update", "remove", "header-remove", "decoder-remove"} {
			t.Run(closing+"/"+change, func(t *testing.T) {
				removed := strings.HasSuffix(change, "remove")
				d := newSMTestDictionary(creditcontrol.Dictionary())
				cfg := testMessageErrorSettings(d)
				cfg.DPRCloseTimeout = time.Hour
				events := make(chan diam.ProtocolErrorEvent, 8)
				peerNotices := make(chan struct{}, 2)
				cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
				cfg.OnDPR = func(diam.Conn, DisconnectCause) { peerNotices <- struct{}{} }
				sm := mustNewStateMachine(t, cfg, d)
				logs := logtest.New()
				opened := make(chan diam.Conn, 1)
				srv := diamtest.NewUnstartedServer(contextAdmissionMessageErrors{sm}, d)
				srv.Config.Logger = logs.Logger()
				srv.Config.OnNewConnection = func(c diam.Conn) {
					c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "peer.example", OriginRealm: "example", CEA: &smparser.CEA{}}))
					opened <- c
				}
				srv.Start()
				defer srv.Close()
				peer, e := net.Dial("tcp", srv.Addr)
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
				var c diam.Conn
				select {
				case c = <-opened:
				case <-time.After(10 * time.Second):
					t.Fatal("connection was not opened")
				}
				makeDPR := func() *diam.Message {
					m := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 17, 18, d)
					mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
					mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
					mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
					return m
				}
				result := make(chan error, 1)
				var response *diam.Message
				if closing == "local" {
					go func() { result <- sm.Disconnect(c, DisconnectBusy, 10*time.Second) }()
					request, e := diam.ReadMessage(peer, d)
					if e != nil {
						t.Fatal(e)
					}
					response = acceptedDWA(t, request, diam.Success)
				} else {
					request := makeDPR()
					_, _ = request.WriteTo(peer)
					answer, e := diam.ReadMessage(peer, d)
					if e != nil || !testResultCode(answer, diam.Success) {
						t.Fatalf("initial DPA=%v %v", answer, e)
					}
					select {
					case <-peerNotices:
					case <-time.After(10 * time.Second):
						t.Fatal("first peerDPR notice missing")
					}
					response = makeDPR()
					response.Header.HopByHopID++
				}
				host := "peer.example"
				if change == "update" {
					host = "updated.example"
					c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: datatype.DiameterIdentity(host), OriginRealm: "example", CEA: &smparser.CEA{}}))
				} else {
					c.SetContext(context.Background())
				}
				setWireIdentity(t, response, avp.OriginHost, host)
				setWireIdentity(t, response, avp.OriginRealm, "example")
				if change == "header-remove" {
					response.Header.CommandFlags |= diam.ProxiableFlag
				}
				if change == "decoder-remove" {
					response.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
				}
				_, _ = response.WriteTo(peer)
				if closing == "local" {
					e := contextAdmissionDisconnectResult(t, result)
					if change == "update" && e != nil || removed && !errors.Is(e, ErrDisconnectClosed) {
						t.Errorf("Disconnect=%v change=%s", e, change)
					}
				} else if change == "update" {
					a, e := diam.ReadMessage(peer, d)
					if e != nil || !testResultCode(a, diam.Success) {
						t.Fatalf("updated peer DPA=%v %v", a, e)
					}
				}

				if removed {
					var b [1]byte
					n, e := peer.Read(b[:])
					if n != 0 || e != io.EOF {
						t.Errorf("revoked Closing wire=%d %v", n, e)
					}
					event := protocolEvent(t, events)
					var code uint32
					if change == "header-remove" {
						code = diam.InvalidHDRBits
					}
					if change == "decoder-remove" {
						code = diam.InvalidAVPLength
					}
					if event.Err.Kind() != diam.ProtocolHandshakeState || event.Err.ResultCode() != code || !event.Closing {
						t.Errorf("revocation notice=%+v", event)
					}
				}
				var texts []string
				for _, record := range logs.Records() {
					texts = append(texts, record.Message)
				}
				wantClosed := closing == "local" || removed
				if c.Closed() != wantClosed {
					t.Fatalf("closed=%t, want %t", c.Closed(), wantClosed)
				}
				if removed {
					if change == "decoder-remove" {
						if len(texts) != 2 || texts[0] != "diam: malformed message" {
							t.Fatalf("decoder logs=%v", texts)
						}
						texts = texts[1:]
					}
					if len(texts) != 1 || texts[0] != "sm: message before CER; closing connection" {
						t.Fatalf("revocation logs=%v", texts)
					}
				} else if len(texts) != 0 {
					t.Fatalf("claim update logs=%v", texts)
				}
				// Join the dispatch batch before checking that no repeat callback ran.
				c.Close()
				if done := connectionDone(c); done != nil {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Fatal("Closing dispatch did not drain")
					}
				}
				if len(peerNotices) != 0 {
					t.Fatal("repeat DPR invoked OnDPR again")
				}

			})
		}
	}
}

// This wrapper forwards both receive paths synchronously while leaving accept
// discovery opaque, as application wrappers around ServeDIAM may do.
type contextAdmissionMessageErrors struct{ sm *StateMachine }

func (h contextAdmissionMessageErrors) ServeDIAM(c diam.Conn, m *diam.Message) {
	h.sm.ServeDIAM(c, m)
}

func (h contextAdmissionMessageErrors) HandleMessageError(c diam.Conn, m *diam.Message, err *diam.MessageError) error {
	return h.sm.HandleMessageError(c, m, err)
}
