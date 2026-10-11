//go:build linux && !386

package sm

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestSCTPEOFPreservesDecodedBusinessAnswer(t *testing.T) {
	requireSCTP(t)
	for _, mode := range []int{1, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			h := newEOFDispatchGate(t)
			server := diamtest.NewUnstartedServerNetwork("sctp", h, dict.Default)
			server.Config.MaxConcurrentHandlers = mode
			server.Start()
			t.Cleanup(func() { h.resume(); server.Close() })
			answers := make(chan *diam.Message, 1)
			mux := diam.NewServeMux()
			mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { answers <- m })
			peer, err := diam.DialNetworkTimeout("sctp", server.Addr, mux, dict.Default, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(peer.Close)
			if _, err := regressionCER(t, dict.Default, 1001).WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			select {
			case cea := <-answers:
				if !testResultCode(cea, diam.Success) {
					t.Fatalf("handshake failed: %v", cea)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("CEA missing")
			}
			answer := diam.NewRequest(999, 1001, dict.Default).Answer(diam.Success)
			if _, err := answer.WriteToStream(peer, 7); err != nil {
				t.Fatal(err)
			}
			select {
			case c := <-h.entered:
				_ = mustConnAs[diam.CloseNotifier](t, c).CloseNotify()
				checkEOFDispatch(t, h, c, answer, peer.Close)
			case <-time.After(3 * time.Second):
				t.Fatal("business callback did not enter before EOF")
			}
		})
	}
}
