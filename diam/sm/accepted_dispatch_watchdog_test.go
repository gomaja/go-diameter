package sm

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
)

// RFC 6733 §5.6: watchdog timer bookkeeping cannot retain the native
// admission barrier while an independent handler or DWR pre-hook is running.
func TestAcceptedWatchdogDispatchReleasesAdmissionWire(t *testing.T) {
	for _, mode := range []int{2, -1} {
		for _, first := range []string{"application", "DWR-hook"} {
			t.Run(fmt.Sprintf("%d/%s", mode, first), func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				block := func(diam.Conn, *diam.Message) { close(entered); <-release }
				p := newProtocolDeliveryWire(t, mode, true, func(cfg *Settings) {
					cfg.EnableWatchdog, cfg.WatchdogInterval = true, time.Hour
					if first == "DWR-hook" {
						cfg.OnDWR = block
					}
				})
				t.Cleanup(unblock)
				later := make(chan struct{}, 1)
				p.sm.Handle("ALL", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
					if m.Header.HopByHopID == 0x93a0 {
						block(c, m)
					} else {
						later <- struct{}{}
					}
				}))
				request := diam.NewMessage(999, diam.RequestFlag, 4, 0x93a0, 0x93a1, p.conn.Dictionary())
				if first == "DWR-hook" {
					request = regressionDWR(t)
					setWireIdentity(t, request, avp.OriginHost, "peer.example")
				}
				p.send(t, request)
				protocolGenerationAwait(t, entered)
				p.send(t, diam.NewMessage(999, diam.RequestFlag, 4, 0x93a2, 0x93a3, p.conn.Dictionary()))
				select {
				case <-later:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("watchdog activity retained admission during an independent callback")
				}
				unblock()
				if first == "DWR-hook" {
					answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
					if err != nil || !testResultCode(answer, diam.Success) {
						t.Fatalf("DWA=%v error=%v", answer, err)
					}
				}
			})
		}
	}
}

// RFC 6733 §§5.4,5.6: a concurrently dispatched handler may synchronously
// Disconnect; its matching DPA must enter while that handler waits.
func TestAcceptedWatchdogHandlerDisconnectWire(t *testing.T) {
	for _, mode := range []int{2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			p := newProtocolDeliveryWire(t, mode, true, func(cfg *Settings) {
				cfg.EnableWatchdog, cfg.WatchdogInterval = true, time.Hour
			})
			result := make(chan error, 1)
			p.sm.Handle("ALL", diam.HandlerFunc(func(c diam.Conn, _ *diam.Message) {
				result <- p.sm.Disconnect(c, DisconnectBusy, 500*time.Millisecond)
			}))
			p.send(t, diam.NewMessage(999, diam.RequestFlag, 4, 0x93b0, 0x93b1, p.conn.Dictionary()))
			request, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("local DPR=%v error=%v", request, err)
			}
			p.send(t, boundWireAnswer(t, p, request, diam.Success))
			if err := protocolGenerationAwait(t, result); err != nil {
				t.Fatalf("matching DPA falsely timed out behind application admission: %v", err)
			}
			select {
			case event := <-p.events:
				t.Fatalf("successful synchronous Disconnect reported protocol failure: %+v", event)
			default:
			}
		})
	}
}
