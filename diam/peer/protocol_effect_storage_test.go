package peer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

func TestCompletedProtocolEffectsReleasePayloads(t *testing.T) {
	s := &session{}
	storage := make([]protocol.Effect, 8)
	for i := range storage {
		storage[i] = protocol.Effect{Kind: protocol.Hold, Token: uint64(i + 1), Input: &protocol.Input{Token: uint64(i + 1)}}
	}
	s.releaseProtocolEffects(storage[:1])
	if cap(s.coreEffects) != cap(storage) || len(s.coreEffects) != 0 {
		t.Fatal("completed batch did not return its storage")
	}
	for _, effect := range storage {
		if effect != (protocol.Effect{}) {
			t.Fatal("completed batch retained a compacted payload")
		}
	}
	// A smaller nested batch cannot displace capacity already returned by another
	// completed decision. Every returned batch releases its own payloads.
	smaller := []protocol.Effect{{Kind: protocol.Hold, Input: &protocol.Input{Token: 99}}}
	s.releaseProtocolEffects(smaller)
	if cap(s.coreEffects) != cap(storage) || smaller[0] != (protocol.Effect{}) {
		t.Fatal("nested completion lost capacity or retained its payload")
	}
}

func TestProtocolBatchStorageIsLentUntilExecutionCompletes(t *testing.T) {
	s := &session{coreEffects: make([]protocol.Effect, 0, 8)}
	// A mismatched connection appends no effects but still owns its borrowed
	// storage until execution ends, so a nested decision cannot overwrite it.
	cfg := protocol.Config{Connection: protocol.Connection{Instance: 1}, Role: protocol.Responder, Local: testBase("local.example.net")}
	core, err := protocol.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.core = core
	s.coreMu.Lock()
	outer := s.handleProtocolLocked(protocol.Input{})
	inner := s.handleProtocolLocked(protocol.Input{})
	s.coreMu.Unlock()
	if cap(outer) != 8 || cap(inner) != 0 {
		t.Fatal("nested decision borrowed an executing batch")
	}
	s.releaseProtocolEffects(inner)
	s.releaseProtocolEffects(outer)
	if cap(s.coreEffects) != 8 {
		t.Fatal("outer batch storage was not returned")
	}
}

func TestNestedProtocolBatchesReuseCompletedStorage(t *testing.T) {
	core, err := protocol.New(protocol.Config{Connection: protocol.Connection{Instance: 1}, Role: protocol.Responder, Local: testBase("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	s := &session{core: core}
	s.releaseProtocolEffects(make([]protocol.Effect, 0, 8))
	s.releaseProtocolEffects(make([]protocol.Effect, 0, 2))
	allocations := testing.AllocsPerRun(100, func() {
		s.coreMu.Lock()
		outer := s.handleProtocolLocked(protocol.Input{})
		inner := s.handleProtocolLocked(protocol.Input{})
		s.coreMu.Unlock()
		if cap(outer) < 8 || cap(inner) < 2 {
			t.Fatal("nested execution lost completed batch storage")
		}
		outer = append(outer, protocol.Effect{Token: 7})
		inner = append(inner, protocol.Effect{Token: 8})
		if outer[0].Token != 7 {
			t.Fatal("nested execution overwrote outer effects")
		}
		s.releaseProtocolEffects(inner)
		s.releaseProtocolEffects(outer)
	})
	if allocations != 0 {
		t.Fatalf("nested protocol execution allocated %.0f buffers", allocations)
	}
}
