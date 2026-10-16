package peer

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func FuzzManagedDWA(f *testing.F) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	request, err := base.BuildDWR(testDict, testBase("local.example.net"), 0)
	if err != nil {
		f.Fatal(err)
	}
	answer, err := base.BuildDWA(request, testBase("known.example.net"))
	if err != nil {
		f.Fatal(err)
	}
	var wire bytes.Buffer
	if _, err = answer.WriteTo(&wire); err != nil {
		f.Fatal(err)
	}
	f.Add(wire.Bytes())
	f.Add(wire.Bytes()[:len(wire.Bytes())-1])
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		msg, err := diam.ReadMessage(bytes.NewReader(raw), testDict)
		if err != nil || msg == nil || msg.Header == nil || msg.Header.CommandCode != diam.DeviceWatchdog || msg.Header.ApplicationID != 0 || msg.Header.CommandFlags&diam.RequestFlag != 0 {
			return
		}
		a, s, _ := newWatchdogTestActor(t, WatchdogReopen)
		// Keep the fuzzer's header/body variation while installing only the owned
		// exchange coordinates, so validation proceeds through the production core.
		valid := testDWA(t, a)
		msg.Header.HopByHopID, msg.Header.EndToEndID = valid.Header.HopByHopID, valid.Header.EndToEndID
		a.onWire(event{s: s, msg: msg})
		if snapshot := s.protocolSnapshot(); snapshot.Watchdog().NumDWA > 1 {
			t.Fatalf("one fuzz input earned multiple recovery credits: %+v", snapshot.Watchdog())
		}
	})
}
