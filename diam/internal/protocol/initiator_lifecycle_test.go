package protocol

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func lifecycleNotices(es []Effect) []Notification {
	var out []Notification
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Kind == HandshakeNotice {
			out = append(out, e.Notification)
		}
	}
	return out
}

func TestInitiatorLifecycleBeforeStart(t *testing.T) {
	for _, role := range []Role{Initiator, Responder} {
		for _, close := range []InputKind{TransportLost, Abort, Retire} {
			t.Run(fmt.Sprintf("role%d/close%d", role, close), func(t *testing.T) {
				c := machine(t, func(cfg *Config) { cfg.Role = role })
				notices := lifecycleNotices(c.Handle(event(close)))
				want := 0
				if role == Initiator {
					want = 1
				}
				if len(notices) != want {
					t.Fatalf("closure before Start produced %d handshake completions, want %d", len(notices), want)
				}
				if len(notices) != 0 && close == Abort && notices[0].Outcome != Cancelled {
					t.Fatalf("Abort outcome = %v", notices[0].Outcome)
				}
				wantKinds(t, c.Handle(event(Start)))
				wantKinds(t, c.Handle(event(close)))
			})
		}
	}
}

func TestInitiatorLifecycleAtCERBoundaries(t *testing.T) {
	for _, stage := range []string{"reservation", "selected", "published", "admission", "ready"} {
		for _, close := range []InputKind{TransportLost, Abort, Retire} {
			t.Run(fmt.Sprintf("%s/close%d", stage, close), func(t *testing.T) {
				c := machine(t, func(cfg *Config) {
					cfg.Role, cfg.KeepCERDeadlineAfterTransportLoss = Initiator, true
					cfg.HandshakeTimeout, cfg.CERInterval = 0, time.Second
				})
				start := c.Handle(event(Start))
				var sent Effect
				if stage != "reservation" {
					sent = grant(t, c, start)
				}
				if stage == "published" || stage == "admission" || stage == "ready" {
					c.Handle(complete(sent))
				}
				if stage == "admission" || stage == "ready" {
					cea := cer(t).Answer(diam.Success)
					cea.Header.HopByHopID, cea.Header.EndToEndID = sent.Message.Header.HopByHopID, sent.Message.Header.EndToEndID
					// A valid peer's capability AVPs are the CER fields plus result.
					for _, field := range cer(t).AVP {
						cea.AddAVP(field)
					}
					ready := find(t, c.Handle(receive(cea)), HandshakeReady)
					if stage == "ready" {
						in := event(ReleaseAdmission)
						in.Token = ready.Token
						c.Handle(in)
					}
				}
				before := c.Snapshot().Timer(RetryTimer)
				es := c.Handle(event(close))
				waiting := stage == "reservation" || stage == "selected" || stage == "published"
				if close == TransportLost && waiting {
					if c.Snapshot().Phase() != WaitCEA || len(es) != 0 || c.Snapshot().Timer(RetryTimer) != before {
						t.Fatalf("EOF changed response-window state: %+v / %v", c.Snapshot(), kinds(es))
					}
					// Cancellation remains immediate after the deferred EOF.
					es = c.Handle(event(Abort))
				}
				want := 1
				if stage == "ready" {
					want = 0
				}
				if len(lifecycleNotices(es)) != want || c.Snapshot().Phase() < Closed {
					t.Fatalf("terminal completion: %v, phase %v", lifecycleNotices(es), c.Snapshot().Phase())
				}
				if stage == "selected" {
					// Even after a terminal lifecycle event the writer's completion
					// still disposes the reservation exactly once.
					in := complete(sent)
					in.Err = net.ErrClosed
					c.Handle(in)
					if len(c.Snapshot().Controls()) != 0 {
						t.Fatal("terminal writer pin retained")
					}
				}
			})
		}
	}
}

func TestClientCERWriteErrorEvidence(t *testing.T) {
	for _, stage := range []WriteStage{WrittenStage, SkippedStage} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role, cfg.KeepCERDeadlineAfterTransportLoss = Initiator, true })
			sent := grant(t, c, c.Handle(event(Start)))
			in := complete(sent)
			in.Stage, in.Err, in.Bytes = stage, net.ErrClosed, 0
			es := c.Handle(in)
			if len(lifecycleNotices(es)) != 1 || !errors.Is(c.Snapshot().Handshake().Err(), net.ErrClosed) || len(c.Snapshot().Controls()) != 0 {
				t.Fatalf("write completion lost error or pin: %v / %v", kinds(es), c.Snapshot().Handshake().Err())
			}
			wantKinds(t, c.Handle(in))
		})
	}
}
