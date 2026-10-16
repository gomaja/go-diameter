package sm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestContextAdmissionCompatibility(t *testing.T) {
	for _, origin := range []string{"CER", "CEA", "bare", "both"} {
		for _, variant := range []string{"answer", "request", "unsupported", "dwa-route", "cea-all", "valid-dpa", "message-error", "dwr", "dpr", "malformed-cea", "malformed-dwa", "malformed-dpa", "repeated-cer", "identity-refresh", "cached-apps", "refresh-apps", "metadata-removed", "disconnect-first", "disconnect-refresh", "nil-error"} {
			if (origin == "bare" || origin == "both") && variant != "repeated-cer" {
				continue
			}
			t.Run(origin+"/"+variant, func(t *testing.T) {
				d := newSMTestDictionary(creditcontrol.Dictionary())
				cfg := testMessageErrorSettings(d)
				cfg.EnableWatchdog = true
				cfg.WatchdogInterval = time.Hour
				var onCER, onCEA, onDWR, onDWA, onDPR, handshake, dispatched atomic.Int32
				cfg.OnCER = func(diam.Conn, *diam.Message) { onCER.Add(1) }
				cfg.OnCEA = func(diam.Conn, *diam.Message) { onCEA.Add(1) }
				cfg.OnDWR = func(diam.Conn, *diam.Message) { onDWR.Add(1) }
				cfg.OnDWA = func(diam.Conn, *diam.Message) { onDWA.Add(1) }
				cfg.OnDPR = func(diam.Conn, DisconnectCause) { onDPR.Add(1) }
				cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshake.Add(1) }
				notices := make(chan diam.ProtocolErrorEvent, 16)
				cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { notices <- e }
				sm := mustNewStateMachine(t, cfg, d)
				log := logtest.New()
				for _, req := range []bool{false, true} {
					sm.HandleIdx(diam.CommandIndex{Code: 0xeeff, Request: req}, diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
						dispatched.Add(1)
						if req {
							_, _ = m.Answer(diam.Success).WriteTo(c)
						}
					}))
				}
				barrierDone := make(chan struct{}, 1)
				sm.HandleIdx(diam.CommandIndex{Code: 0xeefe, Request: false}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { barrierDone <- struct{}{} }))
				if variant == "dwa-route" {
					sm.Handle("DWA", diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched.Add(1) }))
				}
				if variant == "cea-all" {
					sm.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched.Add(1) }))
				}
				meta := &smpeer.Metadata{OriginHost: "peer.example", OriginRealm: "example", Applications: []uint32{1001}}
				if origin == "CER" || origin == "both" {
					meta.CER = &smparser.CER{}
				}
				if origin == "CEA" || origin == "both" {
					meta.CEA = &smparser.CEA{}
				}
				opened := make(chan diam.Conn, 1)
				srv := diamtest.NewUnstartedServer(diam.HandlerFunc(sm.ServeDIAM), d)
				srv.Config.Logger = log.Logger()
				srv.Config.OnNewConnection = func(c diam.Conn) {
					ctx := context.Background()
					if variant == "cached-apps" || variant == "refresh-apps" {
						ctx = context.WithValue(ctx, advertisedAppsKey{}, []uint32{1001})
					}
					c.SetContext(smpeer.NewContext(ctx, meta))
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
				var direct string
				if strings.HasPrefix(variant, "disconnect-") {
					result := make(chan error, 1)
					go func() { result <- sm.Disconnect(c, DisconnectBusy, 10*time.Second) }()
					m, e := diam.ReadMessage(peer, d)
					if e == nil {
						if variant == "disconnect-refresh" {
							meta = meta.Clone()
							meta.OriginHost = "updated.example"
							c.SetContext(smpeer.NewContext(context.Background(), meta))
						}
						a := acceptedDWA(t, m, diam.Success)
						setWireIdentity(t, a, avp.OriginHost, string(meta.OriginHost))
						setWireIdentity(t, a, avp.OriginRealm, "example")
						_, _ = a.WriteTo(peer)
					}
					direct = fmt.Sprintf("DPR=%t err=%v", m != nil, contextAdmissionDisconnectResult(t, result))
				} else if variant == "message-error" {
					m := regressionDWR(t)
					err := sm.HandleMessageError(c, m, &diam.MessageError{ResultCode: diam.MissingAVP, Err: errors.New("synthetic missing AVP")})
					a, readErr := diam.ReadMessage(peer, d)
					if readErr != nil {
						t.Fatal(readErr)
					}
					direct = fmt.Sprintf("error=%v reply=%d read=%v", err, protocolAnswerCode(a), readErr)
					event := protocolEvent(t, notices)
					direct += fmt.Sprintf(" event=%s/%d/%t/%d", event.Err.Kind(), event.Err.ResultCode(), event.Closing, event.Reply)
				} else if variant == "metadata-removed" {
					first := diam.NewMessage(0xeeff, 0, 0, 21, 22, d)
					_, _ = first.WriteTo(peer)
					deadline := time.Now().Add(10 * time.Second)
					for dispatched.Load() == 0 {
						if time.Now().After(deadline) {
							t.Fatal("first dispatch missing")
						}
						runtime.Gosched()
					}
					c.SetContext(context.Background())
					m := regressionDWR(t)
					setWireIdentity(t, m, avp.OriginHost, "peer.example")
					setWireIdentity(t, m, avp.OriginRealm, "example")
					_, _ = m.WriteTo(peer)
					var b [1]byte
					n, e := peer.Read(b[:])
					direct = fmt.Sprintf("closed-read=%d/%v", n, e)
					event := protocolEvent(t, notices)
					direct += fmt.Sprintf(" event=%s/%d/%t", event.Err.Kind(), event.Err.ResultCode(), event.Closing)
				} else if variant == "nil-error" {
					direct = fmt.Sprintf("error=%v", sm.HandleMessageError(c, diam.NewMessage(diam.DeviceWatchdog, 0, 0, 17, 18, d), nil))
				} else {
					m := diam.NewMessage(0xeeff, 0, 0, 17, 18, d)
					expectReply := false
					switch variant {
					case "request":
						m.Header.CommandFlags = diam.RequestFlag
						expectReply = true
					case "unsupported", "cached-apps", "refresh-apps":
						m.Header.CommandFlags = diam.RequestFlag
						m.Header.ApplicationID = 1001
						expectReply = true
						if variant == "refresh-apps" {
							first := diam.NewMessage(0xeeff, 0, 0, 21, 22, d)
							_, _ = first.WriteTo(peer)
							deadline := time.Now().Add(10 * time.Second)
							for dispatched.Load() == 0 {
								if time.Now().After(deadline) {
									t.Fatal("first dispatch missing")
								}
								runtime.Gosched()
							}
							c.SetContext(smpeer.NewContext(context.Background(), meta))
						}
					case "dwr", "identity-refresh":
						if variant == "identity-refresh" {
							_, _ = m.WriteTo(peer)
							deadline := time.Now().Add(10 * time.Second)
							for dispatched.Load() == 0 {
								if time.Now().After(deadline) {
									t.Fatal("initial dispatch did not complete")
								}
								runtime.Gosched()
							}
							meta = &smpeer.Metadata{OriginHost: "new.example", OriginRealm: "newrealm", Applications: []uint32{1001}, CER: meta.CER, CEA: meta.CEA}
							c.SetContext(smpeer.NewContext(context.Background(), meta))
						}
						m = regressionDWR(t)
						setWireIdentity(t, m, avp.OriginHost, string(meta.OriginHost))
						setWireIdentity(t, m, avp.OriginRealm, string(meta.OriginRealm))
						expectReply = true
					case "dpr":
						m = diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 17, 18, d)
						mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
						mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
						mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
						expectReply = true
					case "dwa-route", "valid-dpa":
						m = acceptedDWA(t, regressionDWR(t), diam.Success)
						if variant == "valid-dpa" {
							m.Header.CommandCode = diam.DisconnectPeer
						}
					case "cea-all":
						offer := sm.capabilities(c, nil)
						offer.HostIPAddresses = []datatype.Address{localhostAddress}
						var buildErr error
						m, buildErr = base.BuildCEA(regressionCER(t, d, 1001), offer, diam.Success)
						if buildErr != nil {
							t.Fatal(buildErr)
						}
					case "malformed-cea":
						m.Header.CommandCode = diam.CapabilitiesExchange
					case "malformed-dwa":
						m.Header.CommandCode = diam.DeviceWatchdog
					case "malformed-dpa":
						m.Header.CommandCode = diam.DisconnectPeer
					case "repeated-cer":
						m = regressionCER(t, d, 1001)
					}
					_, e = m.WriteTo(peer)
					if e != nil {
						t.Fatal(e)
					}
					if expectReply {
						a, e := diam.ReadMessage(peer, d)
						if e != nil {
							t.Fatalf("expected reply: %v", e)
						}
						direct = fmt.Sprintf("replyCommand=%d code=%d", a.Header.CommandCode, protocolAnswerCode(a))
					}
					// The registered answer handler is an ordering barrier after the
					// preceding input, including its protocol observations.
					if variant == "dpr" {
						deadline := time.Now().Add(10 * time.Second)
						for onDPR.Load() == 0 {
							if time.Now().After(deadline) {
								t.Fatal("DPR callback missing")
							}
							runtime.Gosched()
						}
					} else {
						barrier := diam.NewMessage(0xeefe, 0, 0, 19, 20, d)
						_, _ = barrier.WriteTo(peer)
						select {
						case <-barrierDone:
						case <-time.After(10 * time.Second):
							t.Fatal("dispatch barrier missing")
						}
						for len(notices) > 0 {
							event := <-notices
							direct += fmt.Sprintf(" event=%s/%d/%t/%d", event.Err.Kind(), event.Err.ResultCode(), event.Closing, event.Reply)
						}
					}
				}
				var logs []string
				for _, r := range log.Records() {
					if r.Message != "sm: unhandled answer discarded" {
						logs = append(logs, fmt.Sprintf("%s:%s:%v", r.Level, r.Message, logtest.Attr(r, "error").Any()))
					}
				}
				wantDispatch := int32(0)
				switch variant {
				case "answer", "request", "identity-refresh", "refresh-apps", "metadata-removed", "dwa-route", "cea-all":
					wantDispatch = 1
				}
				if dispatched.Load() != wantDispatch {
					t.Fatalf("dispatches=%d, want %d", dispatched.Load(), wantDispatch)
				}
				wantCER, wantDWR, wantDWA, wantDPR := int32(0), int32(0), int32(0), int32(0)
				if variant == "repeated-cer" && (origin == "CEA" || origin == "both") {
					wantCER = 1
				}
				if variant == "dwr" || variant == "identity-refresh" {
					wantDWR = 1
					wantDWA = 1
				}
				if variant == "dpr" {
					wantDPR = 1
				}
				if onCER.Load() != wantCER || onCEA.Load() != 0 || onDWR.Load() != wantDWR || onDWA.Load() != wantDWA || onDPR.Load() != wantDPR || handshake.Load() != 0 {
					t.Fatalf("callbacks=%d/%d/%d/%d/%d/%d, want %d/0/%d/%d/%d/0", onCER.Load(), onCEA.Load(), onDWR.Load(), onDWA.Load(), onDPR.Load(), handshake.Load(), wantCER, wantDWR, wantDWA, wantDPR)
				}
				wantDirect, wantLog := "", ""
				switch variant {
				case "request":
					wantDirect = "replyCommand=61183 code=2001"
				case "unsupported", "refresh-apps":
					wantDirect = "replyCommand=61183 code=3007 event=unsupported_application/3007/false/2"
					wantLog = "INFO:sm: unsupported command answered:<nil>"
				case "cached-apps":
					wantDirect = "replyCommand=61183 code=3001 event=unsupported_command/3001/false/2"
					wantLog = "INFO:sm: unsupported command answered:<nil>"
				case "dwr", "identity-refresh":
					wantDirect = "replyCommand=280 code=2001"
				case "dpr":
					wantDirect = "replyCommand=282 code=2001"
				case "malformed-cea":
					wantDirect = " event=cea_rejected/5005/false/0"
				case "malformed-dwa":
					wantDirect = " event=invalid_dwa/5005/false/0"
				case "malformed-dpa":
					wantDirect = " event=invalid_dpa/5005/false/0"
				case "repeated-cer":
					if origin == "CEA" || origin == "both" {
						wantDirect = " event=unexpected_message/0/false/0"
						wantLog = "WARN:sm: ignoring CER on admitted connection; accepted CER renewal is disabled or ineligible:<nil>"
					}
				case "metadata-removed":
					wantDirect = "closed-read=0/EOF event=handshake_state/0/true"
					wantLog = "WARN:sm: message before CER; closing connection:<nil>"
				case "disconnect-first", "disconnect-refresh":
					wantDirect = "DPR=true err=<nil>"
				case "nil-error":
					wantDirect = "error=<nil>"
				case "valid-dpa":
					wantDirect = " event=unexpected_message/0/false/0"
				case "message-error":
					wantDirect = "error=<nil> reply=5005 read=<nil> event=malformed_message/5005/false/2"
				}
				if strings.HasPrefix(variant, "malformed-") {
					wantLog = "WARN:sm: invalid base message:diameter message error 5005: Diameter validation failed (5005): required AVP missing"
					records := log.Records()
					if len(records) != 1 {
						t.Fatalf("malformed records=%#v", records)
					}
					var cause *diam.MessageError
					if !errors.As(logtest.Attr(records[0], "error").Any().(error), &cause) {
						t.Fatalf("malformed log lost MessageError: %#v", records[0])
					}
				}
				if direct != wantDirect {
					t.Fatalf("result %q, want %q", direct, wantDirect)
				}
				if got := strings.Join(logs, "|"); got != wantLog {
					t.Fatalf("records %q, want %q", got, wantLog)
				}
				wantClosed := strings.HasPrefix(variant, "disconnect-") || variant == "metadata-removed"
				if c.Closed() != wantClosed {
					t.Fatalf("closed=%t, want %t", c.Closed(), wantClosed)
				}

			})
		}
	}
}

func TestContextAdmissionOpaqueLifetime(t *testing.T) {
	c := newHandshakeConn()
	c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: "peer.example", CEA: &smparser.CEA{}}))
	sm := mustNewStateMachine(t, testMessageErrorSettings(c.Dictionary()), c.Dictionary())
	var dispatched int
	sm.HandleIdx(diam.CommandIndex{Code: 0xeeff}, diam.HandlerFunc(func(diam.Conn, *diam.Message) { dispatched++ }))
	sm.ServeDIAM(c, diam.NewMessage(0xeeff, 0, 0, 17, 18, c.Dictionary()))
	if dispatched != 1 || sm.contextCore(c) == nil {
		t.Fatal("opaque connection did not own its admitted core")
	}
	if _, retained := sm.cores.Load(c); retained {
		t.Fatal("StateMachine retained a core with no lifecycle signal")
	}
	if !admittedPeer(c) {
		t.Fatal("storing the core replaced peer metadata")
	}
}

func contextAdmissionDisconnectResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect did not complete")
		return nil
	}
}
