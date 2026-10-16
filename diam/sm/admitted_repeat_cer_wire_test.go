package sm

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// RFC 6733 §§5.3, 5.6: removing external claims in a repeated-CER hook
// restores admission gating without turning that already classified CER into
// another capabilities exchange.
func TestAdmittedRepeatedCERHookRevocationWire(t *testing.T) {
	for _, shape := range []string{"CEA", "both"} {
		t.Run(shape, func(t *testing.T) {
			d := newSMTestDictionary(creditcontrol.Dictionary())
			cfg := testMessageErrorSettings(d)
			cfg.HostIPAddresses = []datatype.Address{localhostAddress}
			cfg.ValidateRequests = false
			var cerHooks, ceaHooks, handshakes atomic.Int32
			outcomes := make(chan string, 4)
			cfg.OnCER = func(c diam.Conn, _ *diam.Message) {
				cerHooks.Add(1)
				replaceAdmission(c, "absent")
			}
			cfg.OnCEA = func(diam.Conn, *diam.Message) { ceaHooks.Add(1); outcomes <- "CEA" }
			cfg.OnHandshake = func(diam.Conn, *smpeer.Metadata) { handshakes.Add(1) }
			cfg.OnProtocolError = func(e diam.ProtocolErrorEvent) {
				outcomes <- fmt.Sprintf("%s/%d", e.Err.Kind(), e.Err.ResultCode())
			}
			sm := mustNewStateMachine(t, cfg, d)
			sm.HandleIdx(diam.CommandIndex{AppID: 4, Code: 0xeeff, Request: true}, diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
				if _, err := m.Answer(diam.Success).WriteTo(c); err != nil {
					t.Error(err)
				}
			}))
			opened := make(chan diam.Conn, 1)
			srv := diamtest.NewUnstartedServer(diam.HandlerFunc(sm.ServeDIAM), d)
			srv.Config.OnNewConnection = func(c diam.Conn) { replaceAdmission(c, shape); opened <- c }
			srv.Start()
			defer srv.Close()
			peer, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var c diam.Conn
			select {
			case c = <-opened:
			case <-time.After(15 * time.Second):
				t.Fatal("connection was not opened")
			}
			cer := regressionCER(t, d, 1001)
			if _, err := cer.WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			select {
			case outcome := <-outcomes:
				if outcome == "CEA" {
					answer, readErr := diam.ReadMessage(peer, d)
					t.Fatalf("repeated CER produced an admission CEA on the wire: message=%v error=%v", answer, readErr)
				}
				if outcome != fmt.Sprintf("%s/0", diam.ProtocolUnexpectedMessage) {
					t.Fatalf("repeat disposition=%s", outcome)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("repeated CER disposition was not published")
			}
			// Restore claims for a later application frame. Its response is a positive
			// wire fence: any CEA for the repeated CER would arrive before this answer.
			replaceAdmission(c, shape)
			fence := diam.NewMessage(0xeeff, diam.RequestFlag, 4, 31, 32, d)
			if _, err := fence.WriteTo(peer); err != nil {
				t.Fatal(err)
			}
			answer, err := diam.ReadMessage(peer, d)
			if err != nil || answer.Header.CommandCode != fence.Header.CommandCode || answer.Header.HopByHopID != fence.Header.HopByHopID || answer.Header.EndToEndID != fence.Header.EndToEndID || !testResultCode(answer, diam.Success) {
				t.Fatalf("application wire fence=%v error=%v", answer, err)
			}
			if cerHooks.Load() != 1 || ceaHooks.Load() != 0 || handshakes.Load() != 0 {
				t.Fatalf("repeat callbacks CER/CEA/handshake=%d/%d/%d", cerHooks.Load(), ceaHooks.Load(), handshakes.Load())
			}
			if state := sm.acceptedCore(c, nil, false); state == nil || !state.passiveResponder() {
				t.Fatal("repeat transferred external admission ownership")
			}
		})
	}
}
