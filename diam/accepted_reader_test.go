package diam

import (
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"

	"github.com/gomaja/go-diameter/diam/internal/transport"
)

func TestAcceptedReaderDefersPublicMonitorUntilNextRead(t *testing.T) {
	for _, nextGeneration := range []bool{false, true} {
		for _, duringRead := range []bool{false, true} {
			t.Run(fmt.Sprintf("nextGeneration=%t/duringRead=%t", nextGeneration, duringRead), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local, peer := net.Pipe()
					defer func() { _ = local.Close(); _ = peer.Close() }()
					var c *conn
					calls := 0
					var public <-chan struct{}
					raw := signalReadTransport{Conn: local, read: func([]byte) (int, error) {
						calls++
						if c.owner.sr.reading.Load() {
							t.Error("accepted source read entered dialed read bookkeeping")
						}
						if calls == 1 && duringRead {
							public = c.writer.CloseNotify()
						}
						return 0, io.EOF
					}}
					c = (&Server{}).newConn(raw)
					c.accepted = true
					if nextGeneration {
						c = c.owner.newGeneration(c)
						c.owner.current = c
					}
					defer close(c.owner.done)
					private, ok := transport.ReadDone(c.writer)
					if !ok {
						t.Fatal("native read notification unavailable")
					}
					r := c.owner.sr
					if _, err := r.Read(make([]byte, 1)); err != io.EOF {
						t.Fatalf("direct read = %v", err)
					}
					r.Lock()
					latched := r.readGone
					r.Unlock()
					if latched {
						t.Error("accepted direct EOF entered the dialed terminal-read latch")
					}
					select {
					case <-private:
						t.Error("accepted direct EOF published a private read notification")
					default:
					}
					if !duringRead {
						public = c.writer.CloseNotify()
					}
					synctest.Wait()
					if calls != 1 || r.switchPending.Load() {
						t.Fatalf("public registration activated accepted read-ahead: calls=%d pending=%t", calls, r.switchPending.Load())
					}
					select {
					case <-public:
						t.Error("public notification preceded the next accepted reader call")
					default:
					}
					if _, err := r.Read(make([]byte, 1)); err != io.EOF {
						t.Fatalf("monitored read = %v", err)
					}
					synctest.Wait()
					if calls != 2 {
						t.Errorf("source reads = %d, want 2", calls)
					}
					select {
					case <-public:
					default:
						t.Error("public subscriber missed monitored EOF")
					}
				})
			})
		}
	}
}
