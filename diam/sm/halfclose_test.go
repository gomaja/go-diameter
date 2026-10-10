package sm

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §5.6: requests received before Peer-Disc must finish processing.
// Repeat across fresh connections to exercise reader/handler scheduling without
// introducing sleeps or requiring a particular scheduling order.
func TestHalfCloseAnswersPendingRequests(t *testing.T) {
	for _, mode := range []int{0, 1, -1} {
		for _, kind := range []string{"CER", "DWR"} {
			t.Run(fmt.Sprintf("%d/%s", mode, kind), func(t *testing.T) {
				const runs = 50
				answered := 0
				for range runs {
					func() {
						sm := mustNewStateMachine(t, testMessageErrorSettings())
						srv := diamtest.NewUnstartedServer(sm, dict.Default)
						srv.Config.MaxConcurrentHandlers = mode
						srv.Start()
						defer srv.Close()
						c, err := net.DialTimeout("tcp", srv.Addr, 5*time.Second)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = c.Close() }()
						if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Fatal(err)
						}
						request := regressionCER(t, dict.Default, 1001)
						if _, err := request.WriteTo(c); err != nil {
							t.Fatal(err)
						}
						if kind == "DWR" {
							a, err := diam.ReadMessage(c, dict.Default)
							if err != nil || !testResultCode(a, diam.Success) {
								t.Fatalf("CEA=%v err=%v", a, err)
							}
							request = regressionDWR(t)
							if _, err := request.WriteTo(c); err != nil {
								t.Fatal(err)
							}
						}
						if err := c.(*net.TCPConn).CloseWrite(); err != nil {
							t.Fatal(err)
						}
						a, err := diam.ReadMessage(c, dict.Default)
						if err == nil && testResultCode(a, diam.Success) && a.Header.CommandCode == request.Header.CommandCode &&
							a.Header.HopByHopID == request.Header.HopByHopID && a.Header.EndToEndID == request.Header.EndToEndID {
							answered++
						}
					}()
				}
				if answered != runs {
					t.Fatalf("%s then FIN: answered %d/%d", kind, answered, runs)
				}
			})
		}
	}
}
