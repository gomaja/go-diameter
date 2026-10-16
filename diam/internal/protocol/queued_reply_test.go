package protocol

import (
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

type queuedReplyCompleter interface{ CompleteQueuedReply(Input) bool }

func TestQueuedReplyCompletionPreservesOtherObligations(t *testing.T) {
	for _, name := range []string{"success", "post-hook length", "short", "long", "connection", "kind", "queue stage", "skipped stage", "error", "not queued", "not reported", "close after", "handshake", "control", "unknown token", "closing", "closed"} {
		t.Run(name, func(t *testing.T) {
			c := machine(t)
			c.phase = Open
			op := &operation{length: 100, queued: true, reported: true, required: true, notice: &Notification{Protocol: diam.ProtocolUnsupportedCommand}}
			c.operations[42] = op
			in := Input{Kind: WriteResult, Connection: c.cfg.Connection, Token: 42, Stage: WrittenStage, Bytes: 100}
			want := false
			switch name {
			case "success":
				want = true
			case "post-hook length":
				in.ExpectedBytes = 120
				in.Bytes = 120
				want = true
			case "short":
				in.Bytes = 99
			case "long":
				in.Bytes = 101
			case "connection":
				in.Connection.Generation++
			case "kind":
				in.Kind = Receive
			case "queue stage":
				in.Stage = QueueStage
			case "skipped stage":
				in.Stage = SkippedStage
			case "error":
				in.Err = errors.New("write failed")
			case "not queued":
				op.queued = false
			case "not reported":
				op.reported = false
			case "close after":
				op.closeAfter = true
			case "handshake":
				op.handshake = true
			case "control":
				op.control = &control{command: diam.DisconnectPeer, logical: true, writers: 1}
			case "unknown token":
				in.Token++
			case "closing":
				c.phase = Closing
				want = true
			case "closed":
				c.phase = Closed
				want = true
			}
			completer, ok := any(c).(queuedReplyCompleter)
			if !ok {
				t.Fatal("core cannot complete an effect-free queued reply")
			}
			saved := *op
			reference := *c
			copied := *op
			reference.operations = map[uint64]*operation{42: &copied}
			if got := completer.CompleteQueuedReply(in); got != want {
				t.Fatalf("completion=%t want=%t", got, want)
			}
			if !want {
				if c.operations[42] != op || *op != saved || c.phase != reference.phase {
					t.Fatal("fallback changed pending write state")
				}
				return
			}
			if effects := reference.Handle(in); len(effects) != 0 {
				t.Fatalf("successful completion discarded effects: %+v", effects)
			}
			if len(c.operations) != 0 || c.phase != reference.phase {
				t.Fatal("successful completion retained operation or changed phase")
			}
			if completer.CompleteQueuedReply(in) {
				t.Fatal("completed token consumed twice")
			}
		})
	}
}
