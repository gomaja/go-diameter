package peer

import (
	"sync"
	"testing"
)

func TestEndToEndAllocatorPrefixCounterWrap(t *testing.T) {
	a := endToEndAllocator{}
	a.next.Store((0xabc << 20) | 0xffffe)
	for _, want := range []uint32{0xabcffffe, 0xabcfffff, 0xabd00000} {
		if got := a.allocate(); got != want {
			t.Fatalf("got %08x want %08x", got, want)
		}
	}
}

func TestEndToEndAllocatorConcurrentUnique(t *testing.T) {
	a := endToEndAllocator{}
	a.next.Store(0x12345678)
	const workers, count = 16, 4096
	ids := make(chan uint32, workers*count)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range count {
				ids <- a.allocate()
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := make(map[uint32]bool)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate %08x", id)
		}
		seen[id] = true
	}
	if len(seen) != workers*count {
		t.Fatalf("got %d IDs", len(seen))
	}
}
