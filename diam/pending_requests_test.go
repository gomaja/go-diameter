package diam

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

type pendingWriteTimeout struct{}

func (pendingWriteTimeout) Error() string   { return "synthetic write timeout" }
func (pendingWriteTimeout) Timeout() bool   { return true }
func (pendingWriteTimeout) Temporary() bool { return true }

func TestPendingRequestFreezeAndFailedPublication(t *testing.T) {
	p := new(PendingRequests)
	request := NewRequest(999, 42, dict.Default)
	data, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	failed := p.BeginWrite(data)
	failed(false)
	if p.HasPending() {
		t.Fatal("failed write retained request")
	}
	complete := p.BeginWrite(data)
	complete(true)
	p.CloseAdmission()
	later := NewRequest(999, 42, dict.Default)
	data, err = later.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p.BeginWrite(data)(true)
	if p.MatchAnswer(later.Answer(Success), true) {
		t.Fatal("post-Closing request admitted answer")
	}
	for _, field := range []string{"hop", "end", "command", "application", "request"} {
		answer := request.Answer(Success)
		switch field {
		case "hop":
			answer.Header.HopByHopID++
		case "end":
			answer.Header.EndToEndID++
		case "command":
			answer.Header.CommandCode++
		case "application":
			answer.Header.ApplicationID++
		case "request":
			answer.Header.CommandFlags |= RequestFlag
		}
		if p.MatchAnswer(answer, true) {
			t.Fatalf("%s mismatch consumed ownership", field)
		}
	}
	if !p.MatchAnswer(request.Answer(Success), true) || p.MatchAnswer(request.Answer(Success), true) {
		t.Fatal("answer did not consume ownership exactly once")
	}
}

func FuzzPendingRequestOwnership(f *testing.F) {
	request := NewRequest(999, 42, dict.Default)
	data, err := request.Serialize()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := new(PendingRequests)
		finish := p.BeginWrite(data)
		finish(false)
		if p.HasPending() {
			t.Fatal("failed publication retained ownership")
		}
		p.CloseAdmission()
		p.BeginWrite(data)(true)
		if p.HasPending() {
			t.Fatal("frozen tracker admitted a request")
		}
	})
}

func TestPendingRequestOverlappingFailedRetries(t *testing.T) {
	p := new(PendingRequests)
	request := NewRequest(999, 42, dict.Default)
	data, err := request.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	// Two same-identifier logical retransmissions overlap the serialized writes.
	// Neither outer owner may restore an inner write that already failed.
	firstOuter := p.BeginWrite(data)
	firstInner := p.BeginWrite(data)
	secondOuter := p.BeginWrite(data)
	firstInner(false)
	firstOuter(false)
	secondInner := p.BeginWrite(data)
	secondInner(false)
	secondOuter(false)
	if p.HasPending() {
		t.Fatal("overlapping failed retries resurrected a request that was never sent")
	}
}
