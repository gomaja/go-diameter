package diam

import (
	"errors"
	"sync"
)

// ErrConnectionClosing rejects requests whose write call acquires the
// connection's write gate after Closing is latched (RFC 6733 §5.6).
// Every transport uses this boundary. An admitted write may already have sent
// bytes even if it blocks or fails, so it remains likely in flight (§5.4) until
// its request completes. Queued writes own no answers and cannot publish later.
var ErrConnectionClosing = errors.New("diam: connection is Closing")

// ErrRequestCompleted rejects a reserved write completed before gate admission.
var ErrRequestCompleted = errors.New("diam: request completed before publication")

// PendingRequests tracks request ownership for one connection generation.
// Native connections expose it through PendingRequests() *PendingRequests;
// wrappers can forward that method or expose it through Unwrap. Tracking is
// enabled only when the method is called. Gate acquisition and Closing are
// serialized under the same lock, without holding that lock during transport I/O.
type PendingRequests struct {
	mu       sync.Mutex
	closing  bool
	closed   chan struct{}
	pending  map[requestKey]*RequestWrite
	reserved map[requestKey]*RequestWrite
}

// RequestWrite coordinates a selected request with completion and publication.
// It owns no answer until the native connection acquires its write gate.
// Cancel and Release may run concurrently with that acquisition.
type RequestWrite struct {
	tracker   *PendingRequests
	key       requestKey
	done      chan struct{}
	cancelled bool
	// BeginWrite's compatibility tickets can overlap logical retransmissions.
	previous *RequestWrite
	failed   bool
}

type requestKey struct{ hop, end, command, application uint32 }

func keyForRequest(h *Header) requestKey {
	return requestKey{h.HopByHopID, h.EndToEndID, h.CommandCode, h.ApplicationID}
}

func publicationHeader(b []byte) *Header {
	var h Header
	if h.DecodeFromBytes(b) != nil || int(h.MessageLength) != len(b) ||
		h.CommandFlags&RequestFlag == 0 || h.ApplicationID == 0 && h.CommandCode == DisconnectPeer {
		return nil
	}
	return &h
}

// PrepareWrite reserves a selected request without acquiring answer ownership.
// The caller must keep its identifiers unique until Release, call Cancel when
// the request completes, and Release after the selected writer returns or skips
// the write. A cancelled reservation stays visible until Release so a writer
// paused before its native Write call cannot publish a completed request.
func (p *PendingRequests) PrepareWrite(h *Header) *RequestWrite {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reserved == nil {
		p.reserved = make(map[requestKey]*RequestWrite)
	}
	r := &RequestWrite{tracker: p, key: keyForRequest(h), done: make(chan struct{})}
	p.reserved[r.key] = r
	return r
}

// Cancel completes the request, waking queued writers and removing only this
// request's answer ownership. A writer already holding the gate may finish.
func (r *RequestWrite) Cancel() {
	if r == nil {
		return
	}
	p := r.tracker
	p.mu.Lock()
	defer p.mu.Unlock()
	if !r.cancelled {
		r.cancelled = true
		close(r.done)
	}
	if p.pending[r.key] == r {
		delete(p.pending, r.key)
	}
}

// Release disposes of the selection reservation after the writer returns.
// Answer ownership survives until Cancel or a matching answer consumes it.
func (r *RequestWrite) Release() {
	if r == nil {
		return
	}
	p := r.tracker
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reserved[r.key] == r {
		delete(p.reserved, r.key)
	}
}

func (p *PendingRequests) publication(b []byte) *RequestWrite {
	h := publicationHeader(b)
	if h == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := keyForRequest(h)
	if r := p.reserved[key]; r != nil {
		return r
	}
	return &RequestWrite{tracker: p, key: key, done: make(chan struct{})}
}

func (p *PendingRequests) closedLocked() <-chan struct{} {
	if p.closed == nil {
		p.closed = make(chan struct{})
	}
	return p.closed
}

// admit holds the Closing lock while the physical gate becomes owned. Neither
// gate acquisition nor ownership can straddle Closing (RFC 6733 §§5.4, 5.6).
func (r *RequestWrite) admit(acquire func()) error {
	p := r.tracker
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.cancelled {
		return ErrRequestCompleted
	}
	if p.closing {
		return ErrConnectionClosing
	}
	acquire()
	if p.pending == nil {
		p.pending = make(map[requestKey]*RequestWrite)
	}
	p.pending[r.key] = r
	return nil
}

func (r *RequestWrite) closingDone() <-chan struct{} {
	p := r.tracker
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closedLocked()
}

// BeginWrite registers complete request frames before publication, so an
// immediate answer can find its owner (RFC 6733 §§3, 6.2.1). Call the returned
// function with the write outcome. DPR has separate disconnect ownership.
// Closing freezes the set: later writes cannot admit new Closing answers.
// Custom connections must call BeginWrite while acquiring their own write gate;
// native connections coordinate admission internally. PrepareWrite additionally
// coordinates request cancellation with native gate acquisition.
func (p *PendingRequests) BeginWrite(b []byte) func(bool) {
	var header Header
	if header.DecodeFromBytes(b) != nil || int(header.MessageLength) != len(b) ||
		header.CommandFlags&RequestFlag == 0 || header.ApplicationID == 0 && header.CommandCode == DisconnectPeer {
		return func(bool) {}
	}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return func(bool) {}
	}
	if p.pending == nil {
		p.pending = make(map[requestKey]*RequestWrite)
	}
	key := keyForRequest(&header)
	publication := p.reserved[key]
	if publication != nil && publication.cancelled {
		p.mu.Unlock()
		return func(bool) {}
	}
	if publication == nil {
		publication = &RequestWrite{tracker: p, key: key, done: make(chan struct{})}
	}
	if p.pending[key] != publication {
		publication.previous = p.pending[key]
	}
	p.pending[key] = publication
	p.mu.Unlock()
	return func(written bool) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if written {
			// One successful transmission owns this key regardless of prior
			// retransmission outcomes. Older rollback tickets can be released.
			publication.previous = nil
			return
		}
		publication.failed = true
		if p.pending[key] == publication {
			previous := publication.previous
			// An overlapping request may have failed or completed underneath
			// this ticket. Neither may regain ownership on rollback.
			for previous != nil && (previous.failed || previous.cancelled) {
				previous = previous.previous
			}
			if previous == nil {
				delete(p.pending, key)
			} else {
				p.pending[key] = previous
			}
		}
	}
}

// CloseAdmission freezes request ownership at logical Closing (RFC 6733 §5.6).
func (p *PendingRequests) CloseAdmission() {
	p.mu.Lock()
	if !p.closing {
		p.closedLocked()
		p.closing = true
		close(p.closed)
	}
	p.mu.Unlock()
}

// HasPending reports whether requests sent here still await answers (§5.4).
func (p *PendingRequests) HasPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending) != 0
}

// MatchAnswer consumes a matching request once when consume is true. Matching
// includes command, application and both identifiers (RFC 6733 §§3, 6.2.1).
func (p *PendingRequests) MatchAnswer(m *Message, consume bool) bool {
	if m == nil || m.Header == nil || m.Header.CommandFlags&RequestFlag != 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := keyForRequest(m.Header)
	if p.pending[key] == nil {
		return false
	}
	if consume {
		delete(p.pending, key)
	}
	return true
}

// PendingRequests enables tracking on this native connection generation.
func (w *response) PendingRequests() *PendingRequests {
	p := w.requests.Load()
	if p == nil {
		p = new(PendingRequests)
		if !w.requests.CompareAndSwap(nil, p) {
			p = w.requests.Load()
		}
	}
	return p
}

func (w *response) requestPublication(b []byte) *RequestWrite {
	if p := w.requests.Load(); p != nil {
		return p.publication(b)
	}
	return nil
}
