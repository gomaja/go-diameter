package diam

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

// TestAnswerClearsRetransmittedFlag checks the answer header on the wire:
// RFC 6733 §3 forbids the T flag in answers and clears R, while P keeps the
// request's value (§6.2).
func TestAnswerClearsRetransmittedFlag(t *testing.T) {
	req := NewMessage(CapabilitiesExchange, RequestFlag|ProxiableFlag|RetransmittedFlag, 0, 7, 9, dict.Default)
	var buf bytes.Buffer
	if _, err := req.Answer(Success).WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&buf, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.CommandFlags != ProxiableFlag {
		t.Fatalf("answer flags = %#x, want %#x (P only)", got.Header.CommandFlags, ProxiableFlag)
	}
}

// RFC 6733 §§7.1.3 and 7.2: only the 3xxx result class sets E; R, T and
// reserved flags are cleared, while P keeps the request's value.
func TestAnswerResultCodeFlags(t *testing.T) {
	for _, result := range []uint32{0, Success, 2999, 3000, CommandUnsupported, UnableToDeliver, RealmNotServed, TooBusy, LoopDetected, RedirectIndication, ApplicationUnsupported, InvalidHDRBits, InvalidAVPBits, UnknownPeer, 3999, 4000, 4999, 5000, 5999} {
		for _, p := range []uint8{0, ProxiableFlag} {
			t.Run(fmt.Sprintf("%d/P=%#x", result, p), func(t *testing.T) {
				request := NewMessage(999, RequestFlag|ErrorFlag|RetransmittedFlag|0x0f|p, 4, 7, 9, dict.Default)
				var wire bytes.Buffer
				if _, err := request.Answer(result).WriteTo(&wire); err != nil {
					t.Fatal(err)
				}
				answer, err := ReadMessage(&wire, dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				want := p
				if result >= 3000 && result < 4000 {
					want |= ErrorFlag
				}
				if answer.Header.CommandFlags != want {
					t.Fatalf("Result-Code=%d answer flags=%#02x, want %#02x", result, answer.Header.CommandFlags, want)
				}
			})
		}
	}
}
