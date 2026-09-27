package peer

import (
	"testing"
)

func FuzzManagedAnswerMatching(f *testing.F) {
	f.Add(uint32(1), uint32(272), uint32(4), byte(0))
	f.Add(uint32(2), uint32(272), uint32(4), byte(0))
	f.Add(uint32(1), uint32(273), uint32(4), byte(0))
	f.Add(uint32(1), uint32(272), uint32(5), byte(0))
	f.Add(uint32(1), uint32(272), uint32(4), byte(0x80))
	f.Fuzz(func(t *testing.T, end, command, app uint32, flags byte) {
		request := outboundRequest("", "example.net")
		request.Header.EndToEndID = 1
		p := &pendingRequest{msg: request}
		answer := request.Answer(0)
		answer.Header.EndToEndID, answer.Header.CommandCode, answer.Header.ApplicationID, answer.Header.CommandFlags = end, command, app, flags
		want := end == 1 && command == 272 && app == 4 && flags&0x90 == 0
		if got := answerMatches(p, answer); got != want {
			t.Fatalf("match=%v want=%v for %d/%d/%d/%x", got, want, end, command, app, flags)
		}
	})
}

func FuzzEndToEndAllocator(f *testing.F) {
	f.Add(uint32(0xabcfffff), uint16(3))
	f.Add(uint32(0xffffffff), uint16(2))
	f.Fuzz(func(t *testing.T, start uint32, count uint16) {
		a := endToEndAllocator{}
		a.next.Store(start)
		for i := uint32(0); i < uint32(count%1024); i++ {
			if got, want := a.allocate(), start+i; got != want {
				t.Fatalf("got %08x want %08x", got, want)
			}
		}
	})
}
