package observe

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func TestCallRecoversPanicOnceAndReturns(t *testing.T) {
	records := logtest.New()
	Call(records.Logger(), func() { panic("broken callback") })
	got := records.Records()
	if len(got) != 1 || got[0].Level != slog.LevelError || got[0].Message != "diam: protocol error callback panicked" {
		t.Fatalf("records=%v", got)
	}
	if logtest.Attr(got[0], "panic").Any() != "broken callback" {
		t.Fatalf("panic value lost: %v", got[0])
	}
	stack := logtest.Attr(got[0], "stack").String()
	if len(stack) > 64<<10 || !strings.Contains(stack, "TestCallRecoversPanicOnceAndReturns") {
		t.Fatalf("invalid bounded stack: %q", stack)
	}
	Call(records.Logger(), nil)
	if len(records.Records()) != 1 {
		t.Fatal("nil callback produced a record")
	}
}
