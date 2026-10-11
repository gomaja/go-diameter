//go:build linux && !386 && sctprestart

package sm

import (
	"context"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestAcceptedSCTPRestartWire runs peers and packet capture in two privileged
// Docker containers, never on the host network. See testdata/sctprestart/README.md.
func TestAcceptedSCTPRestartWire(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-20*time.Second))
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "diam/sm/testdata/sctprestart/run.sh"), root, t.TempDir(), "basic")
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("SCTP restart wire harness: %v", err)
	}
}
