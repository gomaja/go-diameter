package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// Private watchdog tests start after capability exchange. Drive the real
// initiator transitions without CER I/O; integration tests cover that I/O and
// the public handshake hooks. Everything after admission uses the executor.
func primeClientTestCore(t *testing.T, cli *Client, c diam.Conn) *acceptedHandshake {
	t.Helper()
	local := cli.capabilitySettings([]datatype.Address{localhostAddress})
	state, batch, err := cli.newCore(c, local)
	if err != nil {
		t.Fatal(err)
	}
	var reservation protocol.Effect
	for _, e := range batch.effects {
		if e.Kind == protocol.ReserveIDs {
			reservation = e
		}
	}
	if reservation.Token == 0 {
		t.Fatalf("initiator setup did not reserve CER: %+v", batch.effects)
	}
	batch = state.prepare(protocol.Input{Kind: protocol.ReserveResult, Token: reservation.Token,
		Reservation: protocol.Reservation{Token: reservation.Token, Hop: 101, End: 102}})
	var sent protocol.Effect
	for _, e := range batch.effects {
		if e.Kind == protocol.Send {
			sent = e
		}
	}
	if sent.Token == 0 {
		t.Fatal("initiator setup did not select CER")
	}
	state.mu.Lock()
	state.core.Handle(protocol.Input{Kind: protocol.WriteResult, Connection: state.id, At: time.Now(), Token: sent.Token, Stage: protocol.WrittenStage,
		Bytes: int64(sent.Message.Len()), ExpectedBytes: int64(sent.Message.Len())})
	state.mu.Unlock()
	remote := local
	remote.OriginHost, remote.OriginRealm = clientSettings.OriginHost, clientSettings.OriginRealm
	if meta, ok := smpeer.FromContext(c.Context()); ok && len(meta.OriginHost) != 0 && len(meta.OriginRealm) != 0 {
		remote.OriginHost, remote.OriginRealm = meta.OriginHost, meta.OriginRealm
	}
	answer, err := base.BuildCEA(sent.Message, remote, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	batch = state.prepare(protocol.Input{Kind: protocol.Receive, Message: answer})
	for {
		var hook *protocol.Effect
		for i := range batch.effects {
			if batch.effects[i].Kind == protocol.RunHook {
				hook = &batch.effects[i]
				break
			}
		}
		if hook == nil {
			break
		}
		batch = state.prepare(protocol.Input{Kind: protocol.Continue, Token: hook.Token, Message: hook.Message})
	}
	for _, effect := range batch.effects {
		if effect.Kind == protocol.Publish {
			state.run(acceptedBatch{effects: []protocol.Effect{effect}})
		}
	}
	cli.Handler.registerAcceptedWatchdog(state)
	state.apply(protocol.Input{Kind: protocol.ReleaseAdmission, Token: state.snapshot().Admission()})
	if state.snapshot().Phase() != protocol.Open || !state.snapshot().Ready() {
		t.Fatalf("initiator setup did not finish admission: %v; %+v", state.snapshot().Handshake().Err(), state.snapshot())
	}
	t.Cleanup(func() {
		state.apply(protocol.Input{Kind: protocol.Retire})
		c.Close()
	})
	return state
}

func expireClientTestWatchdog(state *acceptedHandshake) {
	timer := state.snapshot().Timer(protocol.WatchdogTimer)
	state.apply(protocol.Input{Kind: protocol.TimerExpired, Timer: protocol.WatchdogTimer,
		Token: timer.Token, At: timer.Deadline})
}

func receiveClientTestActivity(state *acceptedHandshake) {
	state.apply(protocol.Input{Kind: protocol.Receive,
		Message: diam.NewRequest(999, 4, state.conn.Dictionary()).Answer(diam.Success), At: time.Now()})
}
