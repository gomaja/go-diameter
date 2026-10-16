package protocol

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/watchdog"
)

func TestCandidateActivationUsesPeerRecoveryHistory(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Watchdog = true; cfg.WatchdogInterval = 6 * time.Second })
	c.Handle(event(Start))
	candidate := find(t, c.Handle(receive(cer(t))), ValidatedCER)
	in := event(Activate)
	in.Token, in.Recovery = candidate.Token, true
	sent := find(t, c.Handle(in), Send)
	ready := find(t, c.Handle(complete(sent)), HandshakeReady)
	in = event(ReleaseAdmission)
	in.Token = ready.Token
	probe := grant(t, c, c.Handle(in))
	if probe.Message.Header.CommandCode != diam.DeviceWatchdog || c.Snapshot().Watchdog().State != watchdog.Reopen {
		t.Fatal("recovered accepted peer skipped REOPEN")
	}
}

func TestCandidateTransfersDeadlineToElectionOwner(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.CandidateDeadlineOwnedByPeer = true })
	c.Handle(event(Start))
	before := c.Snapshot().Timer(HandshakeTimer)
	es := c.Handle(receive(cer(t)))
	find(t, es, ValidatedCER)
	if c.Snapshot().Timer(HandshakeTimer).Token != 0 {
		t.Fatal("candidate retained the pre-CER deadline")
	}
	in := event(TimerExpired)
	in.Timer = HandshakeTimer
	in.Token = before.Token
	in.At = before.Deadline
	if got := c.Handle(in); len(got) != 0 || c.Snapshot().Candidate() == 0 {
		t.Fatal("pre-CER timeout cancelled the election candidate")
	}
}
