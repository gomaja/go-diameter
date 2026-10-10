//go:build linux && !386 && sctpblackhole

package sm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
)

// Run only in an isolated privileged container: this test creates a veth pair
// and a peer namespace. See README's SCTP cancellation validation instructions.
func TestClientSCTPCancellationBlackhole(t *testing.T) {
	for _, phase := range []string{"cer", "tls"} {
		for _, mode := range []string{"cancel", "deadline"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				ip := func(args ...string) {
					t.Helper()
					if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
						t.Fatalf("ip %v: %v: %s", args, err, out)
					}
				}
				ip("netns", "add", "dial-peer")
				defer ip("netns", "del", "dial-peer")
				ip("link", "add", "dial-client", "type", "veth", "peer", "name", "dial-remote")
				defer ip("link", "del", "dial-client")
				ip("link", "set", "dial-remote", "netns", "dial-peer")
				ip("addr", "add", "10.231.71.1/24", "dev", "dial-client")
				ip("link", "set", "dial-client", "up")
				ip("-n", "dial-peer", "link", "set", "lo", "up")
				ip("-n", "dial-peer", "addr", "add", "10.231.71.2/24", "dev", "dial-remote")
				ip("-n", "dial-peer", "link", "set", "dial-remote", "up")
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				proc := exec.Command("ip", "netns", "exec", "dial-peer", exe, "-test.run=^TestSCTPCancellationPeer$", "-test.v")
				proc.Env = append(os.Environ(), "DIAM_SCTP_PEER="+phase)
				stdout, err := proc.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				proc.Stderr = os.Stderr
				if err := proc.Start(); err != nil {
					t.Fatal(err)
				}
				lines := make(chan string, 16)
				scanned := make(chan struct{})
				go func() {
					defer close(scanned)
					scan := bufio.NewScanner(stdout)
					for scan.Scan() {
						lines <- scan.Text()
					}
					if err := scan.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
						t.Errorf("peer output: %v", err)
					}
				}()
				defer func() { _ = proc.Process.Kill(); _ = proc.Wait(); <-scanned }()
				await := func(want string) {
					t.Helper()
					timer := time.NewTimer(2 * time.Second)
					defer timer.Stop()
					for {
						select {
						case line := <-lines:
							if strings.HasPrefix(line, want) {
								return
							}
						case <-timer.C:
							t.Fatalf("peer did not report %s", want)
						}
					}
				}
				await("LISTENING")
				ctx, cancel := context.WithCancel(context.Background())
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				}
				defer cancel()
				cli := newLivenessClient(t)
				cli.RetransmitInterval = 5 * time.Second
				result := make(chan error, 1)
				go func() {
					var c diam.Conn
					var err error
					if phase == "tls" {
						c, err = cli.DialTLSContext(ctx, "sctp4", "10.231.71.2:3868", "", "", nil)
					} else {
						c, err = cli.DialContext(ctx, "sctp4", "10.231.71.2:3868", nil)
					}
					if c != nil {
						c.Close()
					}
					result <- err
				}()
				await("PAYLOAD")
				// Preserve the veth path but remove the peer's address. Its kernel can no
				// longer acknowledge SHUTDOWN. Capturing on dial-client still sees ABORT.
				ip("-n", "dial-peer", "addr", "del", "10.231.71.2/24", "dev", "dial-remote")
				start := time.Now()
				want := error(context.Canceled)
				if mode == "cancel" {
					cancel()
				} else {
					<-ctx.Done()
					start = time.Now()
					want = context.DeadlineExceeded
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("dial = %v, want %v", err, want)
					}
					t.Logf("cancellation returned in %s", time.Since(start))
				case <-time.After(200 * time.Millisecond):
					t.Error("SCTP dial did not return within 200ms of cancellation")
					// Join even on the original graceful-close implementation, and report its
					// actual delay without extending the assertion's bound.
					select {
					case err := <-result:
						t.Logf("dial finally returned after %s: %v", time.Since(start), err)
					case <-time.After(4 * time.Second):
						t.Fatal("SCTP dial did not terminate")
					}
				}
			})
		}
	}

}

func TestSCTPCancellationPeer(t *testing.T) {
	if os.Getenv("DIAM_SCTP_PEER") == "" {
		return
	}
	ln, err := diam.MultistreamListen("sctp4", "10.231.71.2:3868")
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, ln)
	fmt.Println("LISTENING")
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialTest(t, c)
	if os.Getenv("DIAM_SCTP_PEER") == "tls" {
		b := make([]byte, 16384)
		n, err := c.Read(b)
		if err != nil || n == 0 || b[0] != 22 {
			t.Fatalf("ClientHello record = %x: %v", b[:n], err)
		}
	} else {
		m, err := diam.ReadMessage(c, dict.Default)
		if err != nil || m.Header.CommandCode != diam.CapabilitiesExchange {
			t.Fatalf("CER = %v: %v", m, err)
		}
	}
	fmt.Println("PAYLOAD")
	var b [1]byte
	_, _ = c.Read(b[:])
}
