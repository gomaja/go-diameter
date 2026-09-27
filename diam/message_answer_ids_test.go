package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

func TestAnswerCopiesIdentifiersExactly(t *testing.T) {
	for _, tc := range []struct{ hop, end uint32 }{
		{0, 0}, {0, 42}, {42, 0}, {42, 43},
	} {
		request := NewRequest(DeviceWatchdog, 0, dict.Default)
		request.Header.HopByHopID, request.Header.EndToEndID = tc.hop, tc.end
		answer := request.Answer(Success)
		var wire bytes.Buffer
		if _, err := answer.WriteTo(&wire); err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadMessage(&wire, dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Header.HopByHopID != tc.hop || decoded.Header.EndToEndID != tc.end {
			t.Fatalf("answer IDs = (%d,%d), want (%d,%d)", decoded.Header.HopByHopID, decoded.Header.EndToEndID, tc.hop, tc.end)
		}
	}
}
