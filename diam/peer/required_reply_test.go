package peer

import (
	"errors"
	"io"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type requiredReplyConn struct {
	*fakeConn
	failure string
	closes  int
	writes  int
}

func (c *requiredReplyConn) Close() { c.closes++; c.fakeConn.Close() }
func (c *requiredReplyConn) WriteStream(b []byte, _ uint) (int, error) {
	c.writes++
	if c.failure == "short" {
		return len(b) - 1, nil
	}
	return 0, io.ErrClosedPipe
}

func TestRequiredReplyFailureClosesManager(t *testing.T) {
	for _, command := range []string{"CEA", "rejected_CEA", "DWA", "DPA", "unsupported", "rejection", "malformed"} {
		for _, failure := range []string{"queue", "short", "write", "build"} {
			if failure == "build" && (command == "DWA" || command == "DPA" || command == "unsupported") {
				continue
			}
			t.Run(command+"/"+failure, func(t *testing.T) {
				a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
				m := a.m
				c := &requiredReplyConn{fakeConn: s.c.(*fakeConn), failure: failure}
				s.c = c
				s.inbound = true
				s.admitted.Store(true)
				a.cfg.NoAutoReconnect = true
				m.sessions[c] = s
				if !m.CanRenewAcceptedCER(c) {
					t.Fatal("test connection was not eligible for renewal before the failure")
				}
				events := make(chan diam.ProtocolErrorEvent, 8)
				m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
				m.cfg.Settings.HostIPAddresses = testBase("local.example.net").HostIPAddresses
				msg := reviewDWR(t)
				code := uint32(diam.Success)
				if failure == "queue" {
					for len(s.writes) < cap(s.writes) {
						s.writes <- writeRequest{msg: msg}
					}
				}
				if failure == "build" {
					m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
				}
				switch command {
				case "CEA":
					msg = reviewCER(t)
					s.cerRequest = msg
					a.sendCEA(s)
				case "rejected_CEA":
					msg = reviewCER(t)
					code = diam.NoCommonApplication
					m.rejectCER(s, msg, code, errors.New("no common application"))
				case "DWA":
					a.step(rDWR, s, msg)
				case "DPA":
					msg, _ = base.BuildDPR(msg.Dictionary(), testBase("known.example.net"), 0)
					a.answerDPR(s, msg)
				case "unsupported":
					msg = diam.NewMessage(0xeeee, diam.RequestFlag, 0, 11, 12, msg.Dictionary())
					code = diam.CommandUnsupported
					m.unsupported(s, msg)
				case "rejection", "malformed":
					code = diam.MissingAVP
					if failure == "build" {
						msg = diam.NewMessage(0xeeee, diam.RequestFlag, 0, 11, 12, msg.Dictionary())
					}
					if command == "rejection" {
						m.rejectRequest(s, msg, &base.RequestError{Kind: diam.ProtocolInvalidRequest, Code: code}, false, false)
					} else {
						s.first = true
						_ = m.answerMessageError(s, msg, &diam.MessageError{ResultCode: code})
					}
				}
				if failure == "short" || failure == "write" {
					select {
					case w := <-s.writes:
						if !s.writeOne(w) {
							t.Error("failed required answer did not stop its writer")
						}
					default:
						t.Fatal("required answer was not queued")
					}
				}
				if !c.Closed() || c.closes != 1 || !s.terminal.Load() {
					t.Errorf("required %s %s failure: closed=%t closes=%d terminal=%t, want one close", command, failure, c.Closed(), c.closes, s.terminal.Load())
				}
				wantWrites := 0
				if failure == "short" || failure == "write" {
					wantWrites = 1
				}
				if c.writes != wantWrites {
					t.Errorf("reply write attempts=%d, want %d", c.writes, wantWrites)
				}
				if m.CanRenewAcceptedCER(c) {
					t.Error("required reply failure allowed renewal")
				}
				var observed []diam.ProtocolErrorEvent
				for len(events) != 0 {
					observed = append(observed, <-events)
				}
				if len(observed) == 0 {
					t.Fatal("required reply failure produced no typed notification")
				}
				last := observed[len(observed)-1]
				if !last.Closing || last.Reply != diam.ProtocolReplyFailed || last.ReplyCode != code || !last.Message.HasHeader || last.Message.Header != *msg.Header {
					t.Errorf("untruthful failure event: %+v", last)
				}
				if failure == "write" || failure == "short" || command == "CEA" || command == "DWA" || command == "DPA" {
					if !errors.Is(last.Err, diam.ProtocolErrorKind("reply_failure")) {
						t.Errorf("reply failure classification: %v", last.Err)
					}
				}
				if (command == "unsupported" || command == "rejection" || command == "malformed") && (failure == "short" || failure == "write") {
					if len(observed) != 2 || observed[0].Reply != diam.ProtocolReplyQueued || observed[0].Closing {
						t.Errorf("queued and failed completion distinction lost: %+v", observed)
					}
				}
			})
		}
	}
}

func TestRequiredReplyShortWriteWithoutObserver(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	c := &requiredReplyConn{fakeConn: s.c.(*fakeConn), failure: "short"}
	s.c = c
	a.step(rDWR, s, reviewDWR(t))
	if !s.writeOne(requiredQueuedWrite(t, s)) || !c.Closed() || c.closes != 1 {
		t.Fatalf("short required reply without observer: closed=%t closes=%d", c.Closed(), c.closes)
	}
}

func TestRequiredReplyCompletionKeepsRequestMetadata(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	c := &requiredReplyConn{fakeConn: s.c.(*fakeConn), failure: "write"}
	s.c = c
	events := make(chan diam.ProtocolErrorEvent, 2)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	msg := reviewDWR(t)
	original := *msg.Header
	a.step(rDWR, s, msg)
	msg.Header.HopByHopID++
	msg.AVP = nil
	if !s.writeOne(requiredQueuedWrite(t, s)) {
		t.Fatal("failed required reply retained its writer")
	}
	var e diam.ProtocolErrorEvent
	select {
	case e = <-events:
	default:
		t.Fatal("required reply completion produced no notification")
	}
	if !errors.Is(e.Err, diam.ProtocolReplyFailure) || e.Message.Header != original || e.Reply != diam.ProtocolReplyFailed || !e.Closing {
		t.Fatalf("completion lost original request metadata: %+v", e)
	}
}

func requiredQueuedWrite(t *testing.T, s *session) writeRequest {
	t.Helper()
	select {
	case w := <-s.writes:
		return w
	default:
		t.Fatal("required reply was not queued")
		return writeRequest{}
	}
}

func TestRequiredReplyLeaseRejectionReportsCompletion(t *testing.T) {
	a, s, _ := newWatchdogTestActor(t, WatchdogOkay)
	events := make(chan diam.ProtocolErrorEvent, 2)
	a.m.cfg.Settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { events <- e }
	msg := reviewDWR(t)
	a.step(rDWR, s, msg)
	a.discovery.Store(&discoveryState{revoked: true})
	if !s.writeOne(requiredQueuedWrite(t, s)) || !s.c.Closed() {
		t.Fatal("expired lease retained the queued required answer")
	}
	select {
	case e := <-events:
		if !errors.Is(e.Err, diam.ProtocolReplyFailure) || !e.Closing || e.Reply != diam.ProtocolReplyFailed || e.ReplyCode != diam.Success {
			t.Fatalf("lease rejection lost required reply failure: %+v", e)
		}
	default:
		t.Fatal("required reply rejected by the publication gate produced no notification")
	}
}
