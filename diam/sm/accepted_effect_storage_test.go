package sm

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestPreparedEffectsReuseOwnedStorage(t *testing.T) {
	s := &acceptedHandshake{}
	effects := []protocol.Effect{
		{Kind: protocol.StopTimer, Timer: protocol.WatchdogTimer, ReleaseDispatch: true},
		{Kind: protocol.Hold, Input: protocol.Input{Token: 91}},
		{Kind: protocol.Discard, Token: 92},
		{Kind: protocol.Notify, Token: 93},
	}
	release := false
	got := s.prepareLocked(effects, &release)
	if len(got) != 2 || &got[0] != &effects[0] || got[0].Token != 92 || got[1].Token != 93 || !release || len(s.held) != 1 || s.held[0].Token != 91 {
		t.Fatalf("effects=%+v release=%t held=%+v", got, release, s.held)
	}
}

func TestPreparedRecursiveEffectsPreserveUnreadTail(t *testing.T) {
	for _, kind := range []protocol.EffectKind{protocol.ValidatedCER, protocol.FreezeAdmission} {
		t.Run(map[protocol.EffectKind]string{protocol.ValidatedCER: "activate", protocol.FreezeAdmission: "freeze"}[kind], func(t *testing.T) {
			d := newSMTestDictionary(dict.Base())
			cfg := testMessageErrorSettings(d)
			cfg.HandshakeTimeout = -1
			cfg.HostIPAddresses = []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}
			sm := mustNewStateMachine(t, cfg, d)
			c := newHandshakeConn()
			s := sm.acceptedCore(c, nil, true)
			defer s.apply(protocol.Input{Kind: protocol.Abort})
			cer := regressionCER(t, d, 1001)
			var marker protocol.Effect
			if kind == protocol.ValidatedCER {
				hooks := s.core.Handle(protocol.Input{Kind: protocol.Receive, Connection: s.id, Message: cer})
				if len(hooks) != 1 || hooks[0].Kind != protocol.RunHook {
					t.Fatalf("hooks=%+v", hooks)
				}
				candidates := s.core.Handle(protocol.Input{Kind: protocol.Continue, Connection: s.id, Token: hooks[0].Token, Message: hooks[0].Message})
				if len(candidates) != 1 || candidates[0].Kind != kind {
					t.Fatalf("candidates=%+v", candidates)
				}
				marker = candidates[0]
			} else {
				sm.ServeDIAM(c, cer)
				<-c.writes
				effects := s.core.Handle(protocol.Input{Kind: protocol.Disconnect, Connection: s.id})
				for _, e := range effects {
					if e.Kind == kind {
						marker = e
					}
				}
				if marker.Kind != kind {
					t.Fatalf("closing=%+v", effects)
				}
			}
			marker.ReleaseDispatch = true
			effects := []protocol.Effect{marker, {Kind: protocol.Discard, Token: 8001}, {Kind: protocol.Discard, Token: 8002}}
			release := false
			got := s.prepareLocked(effects, &release)
			var kinds []protocol.EffectKind
			for _, e := range got {
				kinds = append(kinds, e.Kind)
			}
			want := []protocol.EffectKind{protocol.Publish, protocol.Send, protocol.Discard, protocol.Discard}
			if kind == protocol.FreezeAdmission {
				want = []protocol.EffectKind{protocol.FreezeAdmission, protocol.ReserveIDs, protocol.Discard, protocol.Discard}
			}
			if !slices.Equal(kinds, want) || got[len(got)-2].Token != 8001 || got[len(got)-1].Token != 8002 || !release {
				t.Fatalf("effects=%+v want kinds=%v release=%t", got, want, release)
			}
		})
	}
}

func TestBatchObserversAllocateOnlyWhenRequired(t *testing.T) {
	s := &acceptedHandshake{}
	in := protocol.Input{Kind: protocol.Receive}
	ordinary := s.batchLocked(in, []protocol.Effect{{Kind: protocol.Discard}, {Kind: protocol.Send, Message: diam.NewRequest(diam.DeviceWatchdog, 0, nil).Answer(diam.Success)}})
	if ordinary.observers != nil || s.observerTail != nil {
		t.Fatal("ordinary effects allocated observers")
	}
	first := s.batchLocked(in, []protocol.Effect{{Kind: protocol.Discard}, {Kind: protocol.Notify, Notification: protocol.Notification{Kind: protocol.WatchdogNotice}}, {Kind: protocol.Discard}})
	if len(first.observers) != 3 || first.observers[0] != nil || first.observers[1] == nil || first.observers[2] != nil {
		t.Fatalf("observer indices=%+v", first.observers)
	}
	second := s.batchLocked(in, []protocol.Effect{{Kind: protocol.Notify, Notification: protocol.Notification{Kind: protocol.WatchdogNotice}}})
	if second.observers[0].previous != first.observers[1].done || s.observerTail != second.observers[0].done {
		t.Fatal("observer order changed")
	}
	first.observers[1].finish()
	second.observers[0].wait()
	second.observers[0].finish()
	compacted := s.batchLocked(in, []protocol.Effect{
		{Kind: protocol.StopTimer, Timer: protocol.WatchdogTimer},
		{Kind: protocol.Notify, Notification: protocol.Notification{Kind: protocol.WatchdogNotice}},
		{Kind: protocol.Hold, Input: protocol.Input{Token: 101}},
		{Kind: protocol.Discard, Token: 102},
		{Kind: protocol.Notify, ReleaseDispatch: true, Notification: protocol.Notification{Kind: protocol.WatchdogNotice}},
	})
	if len(compacted.effects) != 3 || len(compacted.observers) != 3 || compacted.observers[0] == nil || compacted.observers[1] != nil || compacted.observers[2] == nil || !compacted.releaseDispatch || len(s.held) != 1 {
		t.Fatalf("compacted observers=%+v effects=%+v release=%t held=%+v", compacted.observers, compacted.effects, compacted.releaseDispatch, s.held)
	}
	if compacted.effects[1].Token != 102 || compacted.observers[0].previous != second.observers[0].done || compacted.observers[2].previous != compacted.observers[0].done || s.observerTail != compacted.observers[2].done {
		t.Fatal("compaction changed observer indices or order")
	}
	compacted.observers[0].finish()
	compacted.observers[2].wait()
	compacted.observers[2].finish()
}

func TestPreparedEmptyRecursiveEffectsPreserveUnreadTail(t *testing.T) {
	for _, kind := range []protocol.EffectKind{protocol.ValidatedCER, protocol.FreezeAdmission} {
		d := newSMTestDictionary(dict.Base())
		cfg := testMessageErrorSettings(d)
		cfg.HandshakeTimeout = -1
		sm := mustNewStateMachine(t, cfg, d)
		c := newHandshakeConn()
		state := sm.acceptedCore(c, nil, true)
		state.apply(protocol.Input{Kind: protocol.Abort})
		// A selected batch can reach preparation after its generation closes.
		// Its recursive acknowledgement is then empty, but the tail remains.
		effects := []protocol.Effect{{Kind: kind, Token: 9001, ReleaseDispatch: true}, {Kind: protocol.Discard, Token: 9002}, {Kind: protocol.Discard, Token: 9003}}
		release := false
		state.mu.Lock()
		got := state.prepareLocked(effects, &release)
		state.mu.Unlock()
		wantLength := 2
		if kind == protocol.FreezeAdmission {
			wantLength++
		}
		if len(got) != wantLength || got[len(got)-2].Token != 9002 || got[len(got)-1].Token != 9003 || !release {
			t.Fatalf("empty recursion kind=%v effects=%+v release=%t", kind, got, release)
		}
	}
}
