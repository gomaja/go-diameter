package base_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func FuzzValidateBaseMessage(f *testing.F) {
	dictionary := newTestDictionary(dict.Base())
	dictionary.SetStrict(false)
	settings := base.Settings{OriginHost: "local.example.net", OriginRealm: "example.net", VendorID: 1, ProductName: "test",
		HostIPAddresses: []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}}
	for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		m, err := base.BuildCER(dictionary, settings)
		if err != nil {
			f.Fatal(err)
		}
		m.Header.CommandCode = command
		for _, request := range []bool{true, false} {
			candidate := m
			if !request {
				candidate = m.Answer(diam.Success)
			}
			wire, err := candidate.Serialize()
			if err != nil {
				f.Fatal(err)
			}
			f.Add(wire)
		}
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		message, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
		if err != nil || message == nil {
			return
		}
		before, err := message.Serialize()
		if err != nil {
			return
		}
		validationErr := base.ValidateMessage(message)
		after, err := message.Serialize()
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("base validation changed the received message")
		}
		if validationErr != nil && message.Header.CommandFlags&diam.RequestFlag != 0 {
			var evidence []*diam.AVP
			if validationErr.FailedAVP != nil {
				evidence = []*diam.AVP{validationErr.FailedAVP}
			}
			code := validationErr.ResultCode
			if _, err := base.BuildErrorAnswer(message, settings, code, evidence, code >= 3000 && code < 4000); err != nil {
				t.Fatalf("cannot represent base rejection %d: %v", code, err)
			}
		}
	})
}
