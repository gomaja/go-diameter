package protocol

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func TestCompletedAnswerOperationsReuseStorage(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.QueueWrites = true })
	c.phase = Open
	answer := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 31, 32, c.cfg.Dictionary)
	buffer := make([]Effect, 0, 1)
	allocations := testing.AllocsPerRun(100, func() {
		effects := c.send(buffer, answer, nil, true, false, false, nil)
		sent := effects[0]
		queued := event(WriteResult)
		queued.Token = sent.Token
		queued.Stage = QueueStage
		c.HandleInto(queued, buffer[:0])
		if !c.CompleteQueuedReply(complete(sent)) {
			t.Fatal("answer completion retained an obligation")
		}
	})
	if allocations != 0 {
		t.Fatalf("completed answer operation allocated %.0f records; want reused storage", allocations)
	}
}

func TestOperationReusePreservesOutstandingWriters(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.QueueWrites = true })
	c.phase = Open
	answer := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 31, 32, c.cfg.Dictionary)
	first := c.send(nil, answer, nil, true, false, false, nil)[0]
	second := c.send(nil, answer, nil, true, false, false, &Notification{Protocol: diam.ProtocolUnsupportedCommand})[0]
	if c.operations[first.Token] == c.operations[second.Token] {
		t.Fatal("selected writers share an operation record")
	}
	queued := event(WriteResult)
	queued.Stage = QueueStage
	queued.Token = first.Token
	c.Handle(queued)
	if !c.CompleteQueuedReply(complete(first)) {
		t.Fatal("first answer did not complete")
	}
	third := c.send(nil, answer, nil, false, true, true, nil)[0]
	if c.operations[second.Token].notice == nil || c.operations[third.Token].notice != nil || !c.operations[third.Token].handshake || !c.operations[third.Token].closeAfter {
		t.Fatal("reused record changed another writer or retained reply metadata")
	}
	if len(c.Handle(complete(first))) != 0 || len(c.operations) != 2 {
		t.Fatal("duplicate completion consumed a later writer")
	}
	// Ordinary Handle completion releases storage after copying its notice.
	c.Handle(complete(second))
	if c.operations[third.Token] == nil {
		t.Fatal("later reply lost its outstanding completion")
	}
	fourth := c.send(nil, answer, nil, true, false, false, nil)[0]
	if c.operations[third.Token] == c.operations[fourth.Token] || !c.operations[third.Token].handshake || !c.operations[third.Token].closeAfter {
		t.Fatal("reused operation storage overwrote an outstanding writer")
	}
	if c.operations[fourth.Token].notice != nil || c.operations[fourth.Token].handshake || c.operations[fourth.Token].closeAfter {
		t.Fatal("completed record retained prior notification or terminal obligations")
	}
}

func TestCompletedOperationsReleaseProtocolPayloads(t *testing.T) {
	for _, stage := range []WriteStage{QueueStage, WrittenStage, SkippedStage} {
		t.Run(map[WriteStage]string{QueueStage: "queue rejected", WrittenStage: "written", SkippedStage: "skipped control"}[stage], func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.QueueWrites = true })
			c.phase = Open
			answer := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 31, 32, c.cfg.Dictionary)
			var selected *control
			if stage == SkippedStage {
				selected = &control{command: diam.DeviceWatchdog}
			}
			sent := c.send(nil, answer, selected, true, false, false, &Notification{Protocol: diam.ProtocolUnsupportedCommand})[0]
			op := c.operations[sent.Token]
			in := complete(sent)
			in.Stage = stage
			if stage == QueueStage {
				in.Err = diam.ErrConnectionRetired
			}
			effects := c.Handle(in)
			if c.operations[sent.Token] != nil || *op != (operation{}) {
				t.Fatal("terminal writer retained protocol payloads")
			}
			if stage == WrittenStage {
				notice := find(t, effects, Notify).Notification
				if notice.Protocol != diam.ProtocolUnsupportedCommand || notice.Reply != diam.ProtocolReplyWritten {
					t.Fatal("operation disposal changed its completed notice")
				}
			}
		})
	}
}
