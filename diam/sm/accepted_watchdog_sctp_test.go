//go:build linux && !386

package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/testutil"
)

func acceptedWatchdogSCTPSettings(events chan<- WatchdogEvent) *Settings {
	cfg := *serverSettings
	cfg.EnableWatchdog = true
	cfg.WatchdogInterval = 50 * time.Millisecond
	cfg.WatchdogStream = 3
	cfg.watchdogTiming = &watchdogTiming{floor: time.Millisecond}
	cfg.OnWatchdogConnEvent = func(_ diam.Conn, event WatchdogEvent) { events <- event }
	return &cfg
}

func dialAcceptedWatchdogSCTP(t *testing.T, server *diamtest.Server, handler diam.Handler) diam.Conn {
	t.Helper()
	client, err := diam.DialNetworkTimeout("sctp", server.Addr, handler, dict.Default, testutil.SCTPTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := regressionCER(t, dict.Default, 1001).WriteTo(client); err != nil {
		t.Fatal(err)
	}
	return client
}

func waitAcceptedSCTPEvent(t *testing.T, events <-chan WatchdogEvent, want WatchdogEvent) {
	t.Helper()
	select {
	case got := <-events:
		if got != want {
			t.Fatalf("watchdog event = %q, want %q", got, want)
		}
	case <-time.After(testutil.SCTPTimeout):
		t.Fatalf("timed out waiting for watchdog event %q", want)
	}
}

func TestAcceptedWatchdogSCTPStreamAndTimeout(t *testing.T) {
	requireSCTP(t)
	events := make(chan WatchdogEvent, 8)
	server := diamtest.NewServerNetwork("sctp", mustNewStateMachine(t, acceptedWatchdogSCTPSettings(events)), dict.Default)
	defer server.Close()
	cea := make(chan *diam.Message, 1)
	dwr := make(chan *diam.Message, 4)
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { cea <- m })
	mux.HandleFunc("DWR", func(_ diam.Conn, m *diam.Message) { dwr <- m })
	client := dialAcceptedWatchdogSCTP(t, server, mux)
	select {
	case answer := <-cea:
		if !testResultCode(answer, diam.Success) {
			t.Fatalf("CEA result = %v, want success", answer)
		}
	case <-time.After(testutil.SCTPTimeout):
		t.Fatal("timed out waiting for SCTP CEA")
	}
	select {
	case request := <-dwr:
		if request.Header.CommandCode != diam.DeviceWatchdog || request.Header.ApplicationID != 0 || request.Header.CommandFlags&diam.RequestFlag == 0 {
			t.Fatalf("watchdog request header = %+v", request.Header)
		}
		if got := request.MessageStream(); got != 3 {
			t.Fatalf("SCTP DWR stream = %d, want 3", got)
		}
	case <-time.After(testutil.SCTPTimeout):
		t.Fatal("accepted SCTP connection did not receive DWR")
	}
	for _, want := range []WatchdogEvent{WatchdogRequestSent, WatchdogSuspect, WatchdogTimedOut} {
		waitAcceptedSCTPEvent(t, events, want)
	}
	select {
	case unexpected := <-dwr:
		t.Fatalf("sent a second DWR while one was pending: %v", unexpected)
	default:
	}
	select {
	case <-mustConnAs[diam.CloseNotifier](t, client).CloseNotify():
	case <-time.After(testutil.SCTPTimeout):
		t.Fatal("accepted SCTP connection stayed open after watchdog DOWN")
	}
}

func TestAcceptedWatchdogSCTPAnswerOnDifferentStream(t *testing.T) {
	requireSCTP(t)
	events := make(chan WatchdogEvent, 16)
	server := diamtest.NewServerNetwork("sctp", mustNewStateMachine(t, acceptedWatchdogSCTPSettings(events)), dict.Default)
	defer server.Close()
	cea := make(chan *diam.Message, 1)
	type receivedDWR struct {
		conn diam.Conn
		msg  *diam.Message
	}
	dwr := make(chan receivedDWR, 4)
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { cea <- m })
	mux.HandleFunc("DWR", func(c diam.Conn, m *diam.Message) { dwr <- receivedDWR{c, m} })
	client := dialAcceptedWatchdogSCTP(t, server, mux)
	select {
	case answer := <-cea:
		if !testResultCode(answer, diam.Success) {
			t.Fatalf("CEA result = %v, want success", answer)
		}
	case <-time.After(testutil.SCTPTimeout):
		t.Fatal("timed out waiting for SCTP CEA")
	}
	for cycle := range 2 {
		waitAcceptedSCTPEvent(t, events, WatchdogRequestSent)
		var request receivedDWR
		select {
		case request = <-dwr:
		case <-time.After(testutil.SCTPTimeout):
			t.Fatalf("timed out waiting for SCTP DWR cycle %d", cycle+1)
		}
		if got := request.msg.MessageStream(); got != 3 {
			t.Fatalf("SCTP DWR stream = %d, want 3", got)
		}
		// RFC 6733 §5.5.2: DWA need not return on the request's SCTP stream.
		answer, err := base.BuildDWA(request.msg, baseSettings(clientSettings))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := answer.WriteToStream(request.conn, 5); err != nil {
			t.Fatalf("write DWA on SCTP stream 5: %v", err)
		}
		waitAcceptedSCTPEvent(t, events, WatchdogAnswerReceived)
		select {
		case <-mustConnAs[diam.CloseNotifier](t, client).CloseNotify():
			t.Fatal("SCTP connection closed after a valid DWA on stream 5")
		default:
		}
	}
}
