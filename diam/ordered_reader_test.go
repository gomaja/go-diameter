package diam

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type emptyOrderedSource struct{ remaining int }

func (r *emptyOrderedSource) Read([]byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	r.remaining--
	return 0, nil
}

func TestOrderedReaderReusesBuffersForEmptyReads(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
	allocations := testing.AllocsPerRun(20, func() {
		source := &emptyOrderedSource{remaining: 64}
		r.copy(source, func() {})
	})
	t.Logf("allocations per 64 reads: %.2f", allocations)
	if allocations > 40 {
		t.Fatalf("64 empty reads allocated %.0f objects; buffers and successful-read error targets should be reused or avoided", allocations)
	}
}

type orderedSourceResult struct {
	data string
	err  error
}

type scriptedOrderedSource struct {
	results []orderedSourceResult
	reads   chan struct{}
	gate    <-chan struct{}
}

func (r *scriptedOrderedSource) Read(b []byte) (int, error) {
	if len(r.results) == 0 {
		return 0, io.EOF
	}
	if r.gate != nil {
		<-r.gate
	}
	next := r.results[0]
	r.results = r.results[1:]
	n := copy(b, next.data)
	if r.reads != nil {
		r.reads <- struct{}{}
	}
	return n, next.err
}

func TestOrderedReaderRetainsPartialData(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%t", stop), func(t *testing.T) {
			closed := make(chan struct{})
			r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
			first := strings.Repeat("a", 32<<10)
			second := strings.Repeat("b", 32<<10)
			reads := make(chan struct{}, 3)
			source := &scriptedOrderedSource{results: []orderedSourceResult{{first, nil}, {second, io.EOF}}, reads: reads}
			done := make(chan struct{})
			go func() { defer close(done); r.copy(source, func() {}) }()
			stopped := false
			t.Cleanup(func() {
				if !stopped {
					close(closed)
				}
				<-done
			})
			b := make([]byte, 1)
			if n, err := r.Read(b); n != 1 || err != nil || string(b) != "a" {
				t.Fatalf("first read=%d,%v,%q", n, err, b)
			}
			<-reads
			<-reads
			if stop {
				close(closed)
				stopped = true
				<-done
			}
			if n, err := r.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty destination=%d,%v", n, err)
			}
			rest := make([]byte, (32<<10)-1)
			if _, err := io.ReadFull(r, rest); err != nil || string(rest) != first[1:] {
				t.Fatalf("unread first buffer changed: %v", err)
			}
			if stop {
				if n, err := r.Read(b); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed read=%d,%v", n, err)
				}
			} else {
				rest = make([]byte, 32<<10)
				if n, err := r.Read(rest); n != len(rest) || err != io.EOF || string(rest) != second {
					t.Fatalf("second read=%d,%v", n, err)
				}
			}
		})
	}
}

func TestOrderedReaderDeliversDataBeforeRestartAndError(t *testing.T) {
	restart := &TransportRestartError{AssociationID: 42}
	terminal := errors.New("transport stopped")
	for _, final := range []error{io.EOF, terminal} {
		t.Run(final.Error(), func(t *testing.T) {
			closed := make(chan struct{})
			r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
			gate := make(chan struct{}, 1)
			gate <- struct{}{}
			source := &scriptedOrderedSource{results: []orderedSourceResult{{"abc", fmt.Errorf("notification: %w", restart)}, {"de", final}}, gate: gate}
			gone := make(chan struct{}, 2)
			done := make(chan struct{})
			go func() { defer close(done); r.copy(source, func() { gone <- struct{}{} }) }()
			t.Cleanup(func() { close(closed); close(gate); <-done })
			b := make([]byte, 2)
			if n, err := r.Read(b); n != 2 || err != nil || string(b) != "ab" {
				t.Fatalf("partial=%d,%v,%q", n, err, b)
			}
			if len(gone) != 0 {
				t.Fatal("restart retired reader")
			}
			if n, err := r.Read(b); n != 1 || !errors.Is(err, restart) || string(b[:n]) != "c" {
				t.Fatalf("restart=%d,%v,%q", n, err, b[:n])
			}
			gate <- struct{}{}
			if n, err := r.Read(b); n != 2 || err != final || string(b) != "de" {
				t.Fatalf("terminal=%d,%v,%q", n, err, b)
			}
			<-done
			if len(gone) != 1 {
				t.Fatalf("terminal notifications=%d", len(gone))
			}
		})
	}
}

func TestOrderedReaderReusesRejectedBuffers(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
	source := &repeatingOrderedSource{}
	allocations := testing.AllocsPerRun(20, func() {
		for i := 0; i < 64; i++ {
			r.copy(source, func() {})
		}
	})
	t.Logf("allocations per 64 reads: %.2f", allocations)
	if allocations > 40 {
		t.Fatalf("64 rejected handoffs allocated %.0f objects; producer must release rejected buffers", allocations)
	}
}

type repeatingOrderedSource struct{}

func (*repeatingOrderedSource) Read(b []byte) (int, error) { b[0] = 'x'; return 1, nil }

func TestOrderedReaderReusesConsumedBuffers(t *testing.T) {
	allocations := testing.AllocsPerRun(20, func() {
		closed := make(chan struct{})
		r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
		source := &countedOrderedSource{remaining: 64}
		done := make(chan struct{})
		go func() { defer close(done); r.copy(source, func() {}) }()
		b := make([]byte, 1)
		for {
			if _, err := r.Read(b); err != nil {
				break
			}
		}
		<-done
		close(closed)
	})
	t.Logf("allocations per 64 reads: %.2f", allocations)
	if allocations > 40 {
		t.Fatalf("64 consumed buffers allocated %.0f objects; consumer must release drained buffers", allocations)
	}
}

type countedOrderedSource struct{ remaining int }

func (r *countedOrderedSource) Read(b []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	r.remaining--
	b[0] = 'x'
	return 1, nil
}

func TestOrderedReaderSkipsEmptySourceReads(t *testing.T) {
	closed := make(chan struct{})
	r := &orderedReader{events: make(chan restartReadEvent), closed: closed}
	source := &scriptedOrderedSource{results: []orderedSourceResult{{"", nil}, {"ok", io.EOF}}}
	done := make(chan struct{})
	go func() { defer close(done); r.copy(source, func() {}) }()
	t.Cleanup(func() { close(closed); <-done })
	b := make([]byte, 2)
	if n, err := r.Read(b); n != 2 || err != io.EOF || string(b) != "ok" {
		t.Fatalf("read after empty source result=%d,%v,%q", n, err, b)
	}
}

func TestOrderedReaderRetainsBufferUntilFinalByte(t *testing.T) {
	t.Logf("GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
	var mu sync.Mutex
	var released []*[32 << 10]byte
	closed := make(chan struct{})
	r := &orderedReader{
		events: make(chan restartReadEvent), closed: closed,
		testHookBufferReleased: func(buffer *[32 << 10]byte) {
			mu.Lock()
			released = append(released, buffer)
			mu.Unlock()
		},
	}
	first := strings.Repeat("a", 32<<10)
	source := &scriptedOrderedSource{results: []orderedSourceResult{{first, io.EOF}}}
	done := make(chan struct{})
	go func() { defer close(done); r.copy(source, func() {}) }()
	t.Cleanup(func() {
		close(closed)
		<-done
	})
	b := make([]byte, 1)
	if n, err := r.Read(b); n != 1 || err != nil || string(b) != "a" {
		t.Fatalf("partial read=%d,%v,%q", n, err, b)
	}
	buffer := r.pending.buffer
	if buffer == nil {
		t.Fatal("partial read lost its buffer owner")
	}
	<-done
	checkReleases := func(want int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(released) != want {
			t.Fatalf("buffer releases=%d, want %d", len(released), want)
		}
		if want == 1 && released[0] != buffer {
			t.Fatalf("released buffer=%p, want %p", released[0], buffer)
		}
	}
	checkReleases(0)
	rest := make([]byte, (32<<10)-2)
	if n, err := r.Read(rest); n != len(rest) || err != nil || string(rest) != first[1:len(first)-1] {
		t.Fatalf("partial buffer read=%d,%v", n, err)
	}
	checkReleases(0)
	if n, err := r.Read(b); n != 1 || err != io.EOF || string(b) != "a" {
		t.Fatalf("final read=%d,%v,%q", n, err, b)
	}
	checkReleases(1)
}
