package sm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
)

func TestClosingBlockedClientPublicationWire(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			const deadline = 60 * time.Millisecond
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var attempts atomic.Int32
			p := newClientCoreTCPDial(t, func(c *Client) {
				c.EnableWatchdog = true
				c.WatchdogInterval = 20 * time.Millisecond
				c.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
				c.Handler.cfg.DPRCloseTimeout = deadline
			}, func(cli *Client, addr string) (diam.Conn, error) {
				raw, err := net.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				return cli.NewConn(&acceptedCoreBlockedTCP{Conn: raw, entered: entered, release: release, attempts: &attempts, once: &once}, addr)
			})
			admitClientCoreTCP(t, p)
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("DWR did not enter writer")
			}
			defer close(release)
			state := p.client.Handler.acceptedCore(p.conn, nil, false)
			result := make(chan error, 1)
			if local {
				go func() { result <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, deadline) }()
			} else {
				wire := &protocolWire{sm: p.client.Handler, conn: p.conn, peer: p.peer}
				p.send(t, closingContractDPR(t, wire, 500))
			}
			if err := p.peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := p.peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Errorf("blocked watchdog prevented disconnect deadline: bytes=%d error=%v", n, err)
			}
			if !state.watchdogState().stopped.Load() {
				t.Error("Closing latch was not published")
			}
			if local {
				select {
				case err := <-result:
					if !errors.Is(err, ErrDisconnectTimeout) {
						t.Errorf("Disconnect=%v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("deadline/closure did not release publication join")
					p.conn.Close()
				}
			}
			if p.conn.Closed() {
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
			}
		})
	}
}
