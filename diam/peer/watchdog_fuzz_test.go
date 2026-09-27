package peer

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func FuzzManagedDWA(f *testing.F) {
	request, err := base.BuildDWR(dict.Default, testBase("local.example.net"), 0)
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
		msg, err := diam.ReadMessage(bytes.NewReader(raw), dict.Default)
		if err != nil || msg == nil || msg.Header == nil || msg.Header.CommandCode != diam.DeviceWatchdog || msg.Header.ApplicationID != 0 || msg.Header.CommandFlags&diam.RequestFlag != 0 {
			return
		}
		a := actor{cfg: PeerConfig{Host: "known.example.net"}}
		_ = a.validateDWA(msg)
	})
}
