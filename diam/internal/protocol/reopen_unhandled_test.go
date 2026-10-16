package protocol

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
)

func TestReopenDiscardsUnhandledTraffic(t *testing.T) {
	c := supervised(t, true)
	in := receive(diam.NewRequest(999, 4, c.cfg.Dictionary))
	in.Unhandled = true
	es := c.Handle(in)
	for _, e := range es {
		if e.Kind == Send || e.Kind == Admit {
			t.Fatalf("REOPEN selected application work: %+v", e)
		}
	}
	find(t, es, Discard)
}
