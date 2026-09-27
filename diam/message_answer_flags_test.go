package diam

import (
	"bytes"
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
