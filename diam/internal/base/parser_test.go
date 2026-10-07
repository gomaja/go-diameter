package base_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestCapabilityParsersReusableWithoutStateMachine(t *testing.T) {
	request := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dict.Default)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.OriginHost, datatype.DiameterIdentity("peer.example.net")},
		{avp.OriginRealm, datatype.DiameterIdentity("example.net")},
		{avp.AuthApplicationID, datatype.Unsigned32(0xffffffff)},
	} {
		if _, err := request.NewAVP(field.code, avp.Mbit, 0, field.value); err != nil {
			t.Fatal(err)
		}
	}
	parsed := new(base.CER)
	if _, err := parsed.Parse(request, base.ParseOptions{Role: base.Server}); err != nil {
		t.Fatal(err)
	}
	if got := parsed.Applications(); len(got) != 1 || got[0] != 0xffffffff {
		t.Fatalf("applications = %v", got)
	}

	answer := request.Answer(diam.Success)
	parsedAnswer := new(base.CEA)
	if err := parsedAnswer.Parse(answer, base.ParseOptions{Role: base.Client}); err == nil {
		t.Fatal("accepted CEA without Origin-Host and Origin-Realm")
	}
}

func TestRelayCERAlwaysHasCommonApplications(t *testing.T) {
	relay := diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0xffffffff))
	for _, tc := range []struct {
		name     string
		localIDs []uint32
		wantErr  error
	}{
		{"none", []uint32{}, nil},
		{"accounting", []uint32{3}, nil},
		{"dictionary-fallback", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := &base.Application{AuthApplicationID: []*diam.AVP{relay}}
			_, err := parsed.ParseWithApplicationIDs(dict.Default, base.Server, tc.localIDs)
			if err != tc.wantErr {
				t.Fatalf("relay with local applications %v: error = %v, want %v", tc.localIDs, err, tc.wantErr)
			}
		})
	}
}

func TestWatchdogParsersReusableWithoutStateMachine(t *testing.T) {
	request := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 3, 4, dict.Default)
	parsed := new(base.DWR)
	if err := parsed.Parse(request); err != base.ErrMissingOriginHost {
		t.Fatalf("error = %v", err)
	}
	answer := request.Answer(diam.Success)
	parsedAnswer := new(base.DWA)
	if err := parsedAnswer.Parse(answer); err != nil {
		t.Fatal(err)
	}
	if parsedAnswer.ResultCode != diam.Success {
		t.Fatalf("result = %d", parsedAnswer.ResultCode)
	}
}
