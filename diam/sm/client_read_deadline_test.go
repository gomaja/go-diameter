package sm

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestClientReadDeadlineDuringHandler(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, public := range []bool{false, true} {
			for _, readTimeout := range []time.Duration{0, time.Hour} {
				t.Run(fmt.Sprintf("%s/public=%t/readTimeout=%s", network, public, readTimeout), func(t *testing.T) {
					entered, release := make(chan struct{}), make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					defer unblock()
					p := newClientReadPair(t, network, true, 0, func(c *Client) {
						c.ReadTimeout = readTimeout
						c.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(entered); <-release }))
					})
					state := p.admit(t)
					if public {
						mustConnAs[diam.CloseNotifier](t, p.conn).CloseNotify()
					}
					if _, err := diam.NewMessage(999, 0, 4, 123, 456, p.client.Dict).WriteTo(p.peer); err != nil {
						t.Fatal(err)
					}
					protocolGenerationAwait(t, entered)
					// Expire the deadline while dispatch owns the reader. The configured
					// ReadTimeout refreshes it when the next message read begins.
					if err := p.conn.Connection().SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
						t.Fatal(err)
					}
					done := state.watchdogState().exited
					readDone := clientReadDone(t, p.conn)
					if public {
						protocolGenerationAwait(t, done)
					} else {
						select {
						case <-readDone:
							t.Fatal("deadline observed without a socket read")
						default:
						}
						select {
						case <-done:
							t.Fatal("watchdog stopped while the callback owned the reader")
						default:
						}
					}
					if p.conn.Closed() {
						t.Fatal("deadline published Closed before callback completion")
					}
					unblock()
					if public || readTimeout == 0 {
						protocolGenerationAwait(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, p.conn).DispatchDone())
						protocolGenerationAwait(t, done)
						records := p.logs.Records()
						var timeout net.Error
						if len(records) != 1 || records[0].Level != slog.LevelDebug || records[0].Message != "diam: read failed; closing connection" || !errors.As(logError(records[0]), &timeout) || !timeout.Timeout() || !errors.Is(logError(records[0]), os.ErrDeadlineExceeded) {
							t.Fatalf("terminal timeout logs: %+v", records)
						}
						t.Log("expired deadline produced a transport timeout and closed after drain")
					} else {
						request := diam.NewRequest(diam.DeviceWatchdog, 0, p.client.Dict)
						request.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
						request.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
						if _, err := request.WriteTo(p.peer); err != nil {
							t.Fatal(err)
						}
						select {
						case response := <-p.requests:
							if response.Header.CommandCode != diam.DeviceWatchdog || response.Header.CommandFlags&diam.RequestFlag != 0 || !testResultCode(response, diam.Success) {
								t.Fatal(response.Header)
							}
						case <-readDone:
							t.Fatal("read loss published before DWA")
						case <-time.After(10 * time.Second):
							t.Fatal("deadline refresh did not permit DWR/DWA")
						}
						select {
						case <-readDone:
							t.Fatal("read loss published after refreshed read")
						default:
						}
						select {
						case <-done:
							t.Fatal("watchdog stopped after refreshed read")
						default:
						}
						if len(p.logs.Records()) != 0 {
							t.Fatalf("unexpected logs: %+v", p.logs.Records())
						}
						t.Log("expired deadline replaced on next read; DWR/DWA succeeded and watchdog remains active")
					}
					if len(p.events) != 0 {
						t.Fatal("transport deadline emitted a protocol error event")
					}
				})
			}
		}
	}
}
