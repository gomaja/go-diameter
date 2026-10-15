package sm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

type requiredReplyConn struct {
	*handshakeConn
	failure     string
	closes      int
	writes      int
	beforeClose func()
}

func (c *requiredReplyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3868}
}
func (c *requiredReplyConn) Close() {
	c.closes++
	if c.beforeClose != nil {
		c.beforeClose()
	}
	c.handshakeConn.Close()
}
func (c *requiredReplyConn) WriteStream(b []byte, _ uint) (int, error) {
	c.writes++
	if c.failure == "short" {
		return len(b) - 1, nil
	}
	return 0, io.ErrClosedPipe
}

// A required answer that never reaches the transport is just as terminal as
// a failed write. The selected reply status must never claim success.
func TestRequiredReplyFailureClosesStateMachine(t *testing.T) {
	for _, command := range []string{"CEA", "DWA", "DPA", "error", "rejection"} {
		for _, failure := range []string{"short", "write", "build"} {
			if failure == "build" && command != "CEA" && command != "error" && command != "rejection" {
				continue // DWA and DPA builders accept only fixed, infallible scalar data.
			}
			t.Run(command+"/"+failure, func(t *testing.T) {
				c := &requiredReplyConn{handshakeConn: newHandshakeConn(), failure: failure}
				cfg := testMessageErrorSettings(newSMTestDictionary())
				cfg.HostIPAddresses = []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}
				events := make(chan diam.ProtocolErrorEvent, 4)
				cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
				sm := mustNewStateMachine(t, cfg)
				t.Cleanup(sm.HandleAccept(c))
				if command != "CEA" {
					if !sm.completeAcceptedHandshake(c) || !sm.CanRenewAcceptedCER(c) {
						t.Fatal("test connection was not eligible for renewal before the failure")
					}
				}
				c.beforeClose = func() {
					if sm.CanRenewAcceptedCER(c) || !sm.isClosing(c) {
						t.Error("required reply failure did not fence renewal before transport close")
					}
				}
				m := regressionDWR(t)
				code := uint32(diam.Success)
				if command != "CEA" {
					host, _ := m.FindAVP(avp.OriginHost, 0)
					c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: host.Data.(datatype.DiameterIdentity)}))
				}
				if failure == "build" {
					cfg.HostIPAddresses = []datatype.Address{{}}
				}
				switch command {
				case "CEA":
					m = regressionCER(t, m.Dictionary(), 1001)
					handleCER(sm)(c, m)
				case "DWA":
					handleDWR(sm)(c, m)
				case "DPA":
					m = acceptedDPR(t)
					host, _ := m.FindAVP(avp.OriginHost, 0)
					c.SetContext(smpeer.NewContext(context.Background(), &smpeer.Metadata{OriginHost: host.Data.(datatype.DiameterIdentity)}))
					handleDPR(sm)(c, m)
				case "error", "rejection":
					code = diam.MissingAVP
					if failure == "build" {
						m = diam.NewMessage(0xeeee, diam.RequestFlag, 0, 11, 12, m.Dictionary())
					}
					if command == "error" {
						if err := sm.HandleMessageError(c, m, &diam.MessageError{ResultCode: code}); err != nil {
							t.Fatal(err)
						}
					} else {
						sm.rejectRequest(c, m, &base.RequestError{Kind: diam.ProtocolInvalidRequest, Code: code})
					}
				}
				if !c.Closed() || c.closes != 1 {
					t.Errorf("required %s %s failure: closed=%t closes=%d, want one close", command, failure, c.Closed(), c.closes)
				}
				wantWrites := 1
				if failure == "build" {
					wantWrites = 0
				}
				if c.writes != wantWrites {
					t.Errorf("reply write attempts=%d, want %d", c.writes, wantWrites)
				}
				if sm.CanRenewAcceptedCER(c) {
					t.Error("required reply failure allowed renewal")
				}
				select {
				case e := <-events:
					if !e.Closing || e.Reply != diam.ProtocolReplyFailed || e.ReplyCode != code || !e.Message.HasHeader || e.Message.Header != *m.Header {
						t.Errorf("untruthful failure event: %+v", e)
					}
					if command != "error" && command != "rejection" && !errors.Is(e.Err, diam.ProtocolErrorKind("reply_failure")) {
						t.Errorf("reply failure classification: %v", e.Err)
					}
				default:
					t.Error("required reply failure produced no typed notification")
				}
				if len(events) != 0 {
					t.Error("duplicate failure notification")
				}
			})
		}
	}
}

func TestRequiredErrorReplyFailureKeepsMutatedAnswerCode(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "rejection"
		if malformed {
			name = "malformed"
		}
		t.Run(name, func(t *testing.T) {
			p := newProtocolLocalWire(t, func(cfg *Settings, _ *protocolLocalFaults) {
				cfg.RejectUnknownMandatoryAVPs = true
				cfg.OnCEA = func(_ diam.Conn, answer *diam.Message) {
					for _, field := range answer.AVP {
						if field.Code == avp.ResultCode && field.VendorID == 0 {
							field.Data = datatype.Unsigned32(diam.UnableToComply)
						}
					}
				}
			}, false)
			p.faults.write.Store(true)
			request := regressionCER(t, p.sm.cfg.Dict, 1001)
			kind, code := diam.ProtocolUnsupportedAVP, uint32(diam.AVPUnsupported)
			if malformed {
				request.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
				kind, code = diam.ProtocolMalformedMessage, diam.InvalidAVPLength
			} else {
				request.AddAVP(diam.NewAVP(0xfedcab, avp.Mbit, 0, datatype.Unknown{1, 2, 3, 4}))
			}
			header := p.send(t, request)
			event := protocolEvent(t, p.events)
			assertProtocolEvent(t, event, p.conn, &header, kind, code, true, diam.ProtocolReplyFailed, diam.UnableToComply)
			p.eof(t)
		})
	}
}
