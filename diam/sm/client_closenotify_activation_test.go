package sm

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestClientCloseNotifyBeforeDisconnect(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, watchdog := range []bool{false, true} {
			for _, inside := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/watchdog=%t/inside=%t", network, watchdog, inside), func(t *testing.T) {
					entered, release := make(chan struct{}), make(chan struct{})
					public := make(chan (<-chan struct{}), 1)
					defer close(release)
					p := newClientReadPair(t, network, true, 0, func(c *Client) {
						c.EnableWatchdog = watchdog
						c.Handler.Handle("ALL", diam.HandlerFunc(func(conn diam.Conn, _ *diam.Message) {
							if inside {
								public <- mustConnAs[diam.CloseNotifier](t, conn).CloseNotify()
							}
							close(entered)
							<-release
						}))
					})
					state := p.admit(t)
					if _, err := diam.NewMessage(999, 0, 4, 123, 456, p.client.Dict).WriteTo(p.peer); err != nil {
						t.Fatal(err)
					}
					protocolGenerationAwait(t, entered)
					var gone <-chan struct{}
					if inside {
						gone = <-public
					} else {
						gone = mustConnAs[diam.CloseNotifier](t, p.conn).CloseNotify()
					}
					result := make(chan error, 1)
					go func() { result <- p.client.Handler.Disconnect(p.conn, DisconnectBusy, time.Hour) }()
					select {
					case request := <-p.requests:
						if request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
							t.Fatalf("expected DPR, got %+v", request.Header)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("Disconnect did not send DPR while the callback ran")
					}
					awaitReadCondition(t, func() bool {
						for _, control := range state.snapshot().Controls() {
							if control.Command == diam.DisconnectPeer && control.Logical && control.Writers == 0 {
								return true
							}
						}
						return false
					}, "DPR writer did not publish its result")
					timer := state.snapshot().Timer(protocol.ClosingTimer)
					if timer.Token == 0 {
						t.Fatal("Disconnect did not retain its closing deadline")
					}
					closeDialTest(t, p.peer.Connection())
					select {
					case err := <-result:
						if !errors.Is(err, ErrDisconnectClosed) {
							t.Fatalf("Disconnect = %v, want ErrDisconnectClosed", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("public CloseNotify did not observe peer EOF while the callback ran")
					}
					if !time.Now().Before(timer.Deadline) {
						t.Fatal("Disconnect completed only after its deadline")
					}
					select {
					case <-gone:
					default:
						t.Fatal("Disconnect completed without notifying the public subscriber")
					}
				})
			}
		}
	}
}

func TestClientCloseNotifyDuringHandshakeCallback(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			registered := make(chan (<-chan struct{}), 1)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			p := newClientReadPair(t, network, true, 0, func(c *Client) {
				c.EnableWatchdog = false
				c.Handler.cfg.OnHandshake = func(conn diam.Conn, _ *smpeer.Metadata) {
					registered <- mustConnAs[diam.CloseNotifier](t, conn).CloseNotify()
					<-release
				}
			})
			var gone <-chan struct{}
			select {
			case gone = <-registered:
			case <-time.After(5 * time.Second):
				t.Fatal("handshake callback did not register its public subscriber")
			}
			closeDialTest(t, p.peer.Connection())
			select {
			case <-gone:
			case <-time.After(2 * time.Second):
				t.Fatal("public subscriber missed EOF during the handshake callback")
			}
			select {
			case result := <-p.dialed:
				if result.conn != nil {
					result.conn.Close()
				}
				t.Fatalf("Dial returned before the handshake callback: %v", result.err)
			default:
			}
			unblock()
			select {
			case result := <-p.dialed:
				if result.conn != nil {
					result.conn.Close()
				} else if result.err == nil {
					t.Fatal("Dial returned neither a connection nor an error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Dial did not finish after the handshake callback returned")
			}
		})
	}
}
