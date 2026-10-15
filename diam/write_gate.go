package diam

import (
	"sync"
	"time"
)

// writeGate owns one whole transport write. Its state transition can be made
// under the request tracker's Closing lock without holding either lock over I/O.
type writeGate struct {
	mu    sync.Mutex
	held  bool
	ready chan struct{}
}

func (g *writeGate) attempt(r *RequestWrite) (bool, <-chan struct{}, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.held {
		if g.ready == nil {
			g.ready = make(chan struct{})
		}
		return false, g.ready, nil
	}
	acquire := func() { g.held = true }
	if r != nil {
		if err := r.admit(acquire); err != nil {
			return false, nil, err
		}
	} else {
		acquire()
	}
	return true, nil, nil
}

func (g *writeGate) lock(r *RequestWrite) error {
	var closing, completed <-chan struct{}
	if r != nil {
		closing, completed = r.closingDone(), r.done
	}
	for {
		locked, ready, err := g.attempt(r)
		if locked || err != nil {
			return err
		}
		select {
		case <-ready:
		case <-closing:
			return ErrConnectionClosing
		case <-completed:
			return ErrRequestCompleted
		}
	}
}

func (g *writeGate) lockUntil(until time.Time) bool {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	for {
		locked, ready, _ := g.attempt(nil)
		if locked {
			return true
		}
		select {
		case <-ready:
		case <-timer.C:
			return false
		}
	}
}

func (g *writeGate) unlock() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.held = false
	if g.ready != nil {
		close(g.ready)
		g.ready = nil
	}
}
