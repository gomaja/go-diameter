package protocol

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/watchdog"

	"github.com/gomaja/go-diameter/diam"
)

func TestReceiveAppendsOrderedEffectsWithoutAllocating(t *testing.T) {
	c := supervised(t, false)
	h := c
	in := receive(diam.NewMessage(999, 0, 4, 31, 32, c.cfg.Dictionary))
	in.At = epoch.Add(time.Second)
	prefix := Effect{Kind: CancelSend, Token: 987}
	storage := make([]Effect, 1, 16)
	storage[0] = prefix
	var out []Effect
	allocations := testing.AllocsPerRun(100, func() { out = h.HandleInto(in, storage) })
	if allocations != 0 {
		t.Fatalf("reused receive output allocated %g times", allocations)
	}
	if &out[0] != &storage[0] || out[0] != prefix {
		t.Fatal("receive replaced or changed caller prefix")
	}
	wantKinds(t, out[1:], StopTimer, ArmTimer, Admit)
	if out[0].ReleaseDispatch || !out[1].ReleaseDispatch || out[2].ReleaseDispatch || out[3].ReleaseDispatch {
		t.Fatal("receive admission boundary moved from the first new effect")
	}
	if out[3].Message != in.Message {
		t.Fatal("application dispatch lost its message")
	}
	if out[2].Deadline != in.At.Add(6*time.Second) {
		t.Fatal("receive timer did not precede dispatch")
	}
}

func TestHandleKeepsEarlierEffectsAcrossLaterEvents(t *testing.T) {
	c := supervised(t, false)
	in := receive(diam.NewMessage(999, 0, 4, 31, 32, c.cfg.Dictionary))
	first := c.Handle(in)
	saved := append([]Effect(nil), first...)
	in.At = epoch.Add(time.Second)
	second := c.Handle(in)
	if !reflect.DeepEqual(first, saved) {
		t.Fatal("later Handle overwrote a returned effect batch")
	}
	second[0].Token = 99999
	if !reflect.DeepEqual(first, saved) {
		t.Fatal("returned batches share effect storage")
	}
}

func TestCallerEffectStoragePreservesStateTransitions(t *testing.T) {
	for name := range shapes {
		for k := Start; k <= BeginCER; k++ {
			t.Run(name+"/"+fmt.Sprint(k), func(t *testing.T) {
				first, second := matrixSetup(t, name), matrixSetup(t, name)
				in := matrixInput(t, name, k, first)
				want := first.core.Handle(in)
				prefix := Effect{Kind: CancelSend, Token: 987}
				storage := make([]Effect, 1, 32)
				storage[0] = prefix
				got := second.core.HandleInto(in, storage)
				if got[0] != prefix {
					t.Fatal("state transition changed caller prefix")
				}
				if len(got)-1 != len(want) {
					t.Fatalf("effect count=%d want=%d", len(got)-1, len(want))
				}
				for i, e := range want {
					actual := got[i+1]
					if e.Message != nil && actual.Message != nil {
						expectedBytes, err := e.Message.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						actualBytes, err := actual.Message.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(actualBytes, expectedBytes) || actual.Message.MessageStream() != e.Message.MessageStream() {
							t.Fatalf("effect %d message differs", i)
						}
						actual.Message = e.Message // Dictionary and dispatch internals are not effect payloads.
					}
					if !reflect.DeepEqual(actual, e) {
						t.Fatalf("effect %d differs: got=%+v want=%+v", i, actual, e)
					}
				}
				if !reflect.DeepEqual(first.core.Snapshot(), second.core.Snapshot()) {
					t.Fatal("caller storage changed state transition")
				}
			})
		}
	}
}

func TestEffectPayloadStorageRemainsCompact(t *testing.T) {
	size := reflect.TypeFor[Effect]().Size()
	t.Logf("Effect storage: %d bytes", size)
	if size > 512 {
		t.Fatalf("effect occupies %d bytes; optional payloads dominate each obligation", size)
	}
}

func TestHeldReceiveLeavesSequenceAndExpiryPending(t *testing.T) {
	c := supervised(t, false)
	c.ready = false
	expired := event(TimerExpired)
	expired.Timer, expired.Token = WatchdogTimer, c.timers[WatchdogTimer].Token
	expired.At = c.timers[WatchdogTimer].Deadline
	expired.AfterReceive = 1
	c.deferredExpiry = &expired
	in := receive(diam.NewMessage(999, 0, 4, 31, 32, c.cfg.Dictionary))
	in.Sequence = 2
	storage := make([]Effect, 1, 4)
	storage[0] = Effect{Kind: CancelSend, Token: 987}
	out := c.HandleInto(in, storage)
	wantKinds(t, out[1:], Hold)
	if c.receivedSequence != 0 || c.deferredExpiry != &expired {
		t.Fatal("held receive advanced the sequence or consumed its deferred expiry")
	}
	saved := out[1].Input
	if saved == nil || saved.Message == in.Message || saved.Sequence != 2 {
		t.Fatal("held receive did not detach its retained input")
	}
	in.Message.Header.CommandCode = 1000
	out[1] = Effect{}
	if saved.Message.Header.CommandCode != 999 {
		t.Fatal("held payload changed with source message or effect storage")
	}
}

func TestPublishedSnapshotSurvivesOutputReuse(t *testing.T) {
	c := machine(t)
	c.Handle(event(Start))
	storage := make([]Effect, 0, 16)
	effects := c.HandleInto(receive(cer(t)), storage)
	candidate := find(t, effects, ValidatedCER)
	before := candidate.Snapshot
	in := event(Activate)
	in.Token = candidate.Token
	effects = c.HandleInto(in, effects[:0])
	published := find(t, effects, Publish).Snapshot
	if before == nil || published == nil || before == published || before.Phase() != PreCER || published.Phase() != Open {
		t.Fatal("snapshot payloads changed when effect storage was reused")
	}
	before.capabilities.LocalApplications[0] = 999
	if published.Capabilities().LocalApplications[0] != 4 || c.Snapshot().Capabilities().LocalApplications[0] != 4 {
		t.Fatal("snapshot payloads share mutable capability storage")
	}
}

func TestWatchdogRepliesAppendAfterActivityEffects(t *testing.T) {
	c := supervised(t, false)
	prefix := Effect{Kind: CancelSend, Token: 987}
	storage := make([]Effect, 1, 16)
	storage[0] = prefix
	in := receive(request(t, diam.DeviceWatchdog))
	out := c.HandleInto(in, storage)
	wantKinds(t, out[1:], StopTimer, ArmTimer, Send)
	if out[0] != prefix || !out[1].ReleaseDispatch {
		t.Fatal("DWR changed the caller prefix or dispatch boundary")
	}
	sent := out[3]
	if !sent.AnswerHook || !sent.Required || sent.CloseAfter || sent.Message.Header.CommandFlags&diam.RequestFlag != 0 || sent.Message.Header.CommandCode != diam.DeviceWatchdog {
		t.Fatal("DWR lost its required answer obligation")
	}
	c.Handle(complete(sent))
	probeSend := probe(t, c)
	in = receive(dwa(t, probeSend, diam.Success))
	out = c.HandleInto(in, storage)
	wantKinds(t, out[1:], StopTimer, ArmTimer, CompleteRequest, ReleaseIDs, Notify)
	if out[0] != prefix || !out[1].ReleaseDispatch {
		t.Fatal("DWA changed the caller prefix or dispatch boundary")
	}
	if out[5].Notification.Kind != WatchdogNotice || out[5].Notification.Diagnostic != "answer" || c.Snapshot().Watchdog().Pending || c.Snapshot().Watchdog().State != watchdog.Okay {
		t.Fatal("DWA lost its completion or health credit")
	}
}

func TestPeerDisconnectDispatchFollowsReceiptActivity(t *testing.T) {
	c := supervised(t, false)
	prefix := Effect{Kind: CancelSend, Token: 987}
	storage := make([]Effect, 1, 16)
	storage[0] = prefix
	out := c.HandleInto(receive(request(t, diam.DisconnectPeer)), storage)
	wantKinds(t, out[1:], StopTimer, ArmTimer, PeerDisconnectDecision, StopTimer, ArmTimer, FreezeAdmission)
	if out[0] != prefix {
		t.Fatal("peer disconnect changed the caller prefix")
	}
	for i, e := range out {
		if e.ReleaseDispatch != (i == 3) {
			t.Fatalf("peer disconnect dispatch boundary at effect %d is %t", i, e.ReleaseDispatch)
		}
	}
	in := event(Frozen)
	in.Token = out[6].Token
	out = c.HandleInto(in, out[:1])
	wantKinds(t, out[1:], Send)
	if !out[1].Required || out[1].Message.Header.CommandCode != diam.DisconnectPeer || out[1].Message.Header.CommandFlags&diam.RequestFlag != 0 {
		t.Fatal("peer disconnect lost its required answer")
	}
}
