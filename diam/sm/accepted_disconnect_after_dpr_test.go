package sm

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

// RFC 6733 §§5.4–5.6: receiving DPR commits Closing, but the StateMachine's
// existing public Disconnect API can still initiate its own crossed exchange.
func TestAcceptedDisconnectAfterPeerDPRWire(t *testing.T) {
	for _, tc := range []struct {
		name            string
		receiver, local time.Duration
		want            error
		repeat          bool
		log             string
	}{
		{"matching-DPA", time.Second, 500 * time.Millisecond, nil, false, ""},
		{"local-timeout", time.Second, 100 * time.Millisecond, ErrDisconnectTimeout, false, "sm: disconnect timeout; closing connection"},
		{"receiver-deadline", 100 * time.Millisecond, time.Second, ErrDisconnectClosed, false, "sm: Wait-Returns timeout; closing connection"},
		{"repeated-peer-DPR", 200 * time.Millisecond, time.Second, ErrDisconnectClosed, true, "sm: Wait-Returns timeout; closing connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProtocolWire(t, func(cfg *Settings) { cfg.DPRCloseTimeout = tc.receiver }, true)
			peerHeader := p.send(t, closingContractDPR(t, p, 0x92c0))
			answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || !testResultCode(answer, diam.Success) || answer.Header.HopByHopID != peerHeader.HopByHopID || answer.Header.EndToEndID != peerHeader.EndToEndID {
				t.Fatalf("peer DPR answer=%v err=%v", answer, err)
			}
			result := make(chan error, 1)
			go func() { result <- p.sm.Disconnect(p.conn, DisconnectBusy, tc.local) }()
			request, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
			if err != nil || request.Header.CommandCode != diam.DisconnectPeer || request.Header.CommandFlags&diam.RequestFlag == 0 {
				got := protocolGenerationAwait(t, result)
				t.Fatalf("Disconnect after peer DPR did not send local DPR: frame=%v read=%v result=%v", request, err, got)
			}
			switch {
			case tc.want == nil:
				p.send(t, boundWireAnswer(t, p, request, diam.Success))
			case tc.repeat:
				time.Sleep(60 * time.Millisecond)
				repeated := p.send(t, closingContractDPR(t, p, 0x92c2))
				answer, err := diam.ReadMessage(p.peer, p.conn.Dictionary())
				if err != nil || !testResultCode(answer, diam.Success) || answer.Header.HopByHopID != repeated.HopByHopID || answer.Header.EndToEndID != repeated.EndToEndID {
					t.Fatalf("repeated peer DPR answer=%v err=%v", answer, err)
				}
			}
			got := protocolGenerationAwait(t, result)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("matching local DPA: %v", got)
				}
			} else if !errors.Is(got, tc.want) {
				t.Fatalf("Disconnect result=%v want=%v", got, tc.want)
			}
			if !p.conn.Closed() {
				t.Fatal("completed Disconnect left transport open")
			}
			if tc.log != "" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				records, err := p.logs.Wait(ctx, 1)
				if err != nil || len(records) != 1 || records[0].Message != tc.log || records[0].Level != slog.LevelWarn {
					t.Fatalf("timeout records=%v err=%v want=%q", records, err, tc.log)
				}
				cause, _ := logtest.Attr(records[0], "error").Any().(error)
				if tc.want == ErrDisconnectTimeout && !errors.Is(cause, ErrDisconnectTimeout) {
					t.Fatalf("local timeout log lost ErrDisconnectTimeout: %v", cause)
				}
				if tc.want == ErrDisconnectClosed && cause != nil {
					t.Fatalf("receiver timeout fabricated local timeout cause: %v", cause)
				}
				assertProtocolEvent(t, protocolEvent(t, p.events), p.conn, nil, diam.ProtocolDisconnectTimeout, 0, true, diam.ProtocolReplyNone, 0)
			}
		})
	}
}
