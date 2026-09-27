package sm

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestUnsupportedCommandAnswerTCP(t *testing.T) {
	for _, command := range []uint32{0xfedc, diam.ReAuth} {
		t.Run(fmt.Sprint(command), func(t *testing.T) { testUnsupportedCommandAnswerTCP(t, command) })
	}
}

func testUnsupportedCommandAnswerTCP(t *testing.T, command uint32) {
	sm := New(testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	request := diam.NewMessage(command, diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag, 0, 0x1234, 0x5678, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Header.CommandCode != request.Header.CommandCode || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
		t.Fatalf("wrong answer header: %+v", answer.Header)
	}
	if answer.Header.CommandFlags != diam.ErrorFlag|diam.ProxiableFlag {
		t.Fatalf("answer flags = %#x", answer.Header.CommandFlags)
	}
	if !testResultCode(answer, diam.CommandUnsupported) {
		t.Fatalf("answer result code: %v", answer)
	}
	if got := answer.AVP[0].Data; got != testMessageErrorSettings().OriginHost {
		t.Fatalf("Origin-Host = %v", got)
	}
	if got := answer.AVP[1].Data; got != testMessageErrorSettings().OriginRealm {
		t.Fatalf("Origin-Realm = %v", got)
	}
}

func TestUnsupportedCommandNeverAnswersAnswer(t *testing.T) {
	sm := New(testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	answer := diam.NewMessage(0xfedc, 0, 0, 0x1234, 0x5678, dict.Default)
	if _, err := answer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("read = %v, want timeout", err)
	}
}

func TestUnsupportedCommandHonorsAllHandler(t *testing.T) {
	sm := New(testMessageErrorSettings())
	seen := make(chan struct{}, 1)
	sm.HandleFunc("ALL", func(_ diam.Conn, _ *diam.Message) { seen <- struct{}{} })
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	writeValidSMErrorCER(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := diam.ReadMessage(conn, dict.Default); err != nil {
		t.Fatalf("read CEA: %v", err)
	}
	request := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 1, 2, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("ALL handler was not called")
	}
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = diam.ReadMessage(conn, dict.Default)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("read = %v, want timeout", err)
	}
}

// TestUnsupportedCommandStillReported keeps the error report ServeMux sent
// for unhandled messages before the 3001 fallback existed: an unhandled
// request is answered with 3001 and reported, and an unhandled answer is
// reported rather than dropped silently.
func TestUnsupportedCommandStillReported(t *testing.T) {
	sm := New(testMessageErrorSettings())
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	waitReport := func(want string) {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			select {
			case r := <-sm.ErrorReports():
				if r.Error != nil && strings.Contains(r.Error.Error(), want) {
					return
				}
			case <-deadline:
				t.Fatalf("no error report containing %q", want)
			}
		}
	}
	request := diam.NewMessage(0xfedc, diam.RequestFlag, 0, 1, 2, dict.Default)
	if _, err := request.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	waitReport("Code:65244 Request:true")
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if answer, err := diam.ReadMessage(conn, dict.Default); err != nil || !testResultCode(answer, diam.CommandUnsupported) {
		t.Fatalf("want 3001 answer, got %v, %v", answer, err)
	}
	answer := diam.NewMessage(0xfedc, 0, 0, 3, 4, dict.Default)
	if _, err := answer.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	waitReport("Code:65244 Request:false")
}
