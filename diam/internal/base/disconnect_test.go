package base_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestDisconnectValidatorsReusableWithoutStateMachine(t *testing.T) {
	dpr := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 7, 8, dict.Default)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.OriginHost, datatype.DiameterIdentity("peer.example.net")},
		{avp.OriginRealm, datatype.DiameterIdentity("example.net")},
		{avp.DisconnectCause, datatype.Enumerated(1)},
	} {
		if _, err := dpr.NewAVP(field.code, avp.Mbit, 0, field.value); err != nil {
			t.Fatal(err)
		}
	}
	cause, err := base.ValidateDPR(dpr)
	if err != nil || cause != 1 {
		t.Fatalf("DPR cause = %d, error = %v", cause, err)
	}

	dpa := dpr.Answer(diam.Success)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.OriginHost, datatype.DiameterIdentity("peer.example.net")},
		{avp.OriginRealm, datatype.DiameterIdentity("example.net")},
	} {
		if _, err := dpa.NewAVP(field.code, avp.Mbit, 0, field.value); err != nil {
			t.Fatal(err)
		}
	}
	result, err := base.ValidateDPA(dpa)
	if err != nil || result != diam.Success {
		t.Fatalf("DPA result = %d, error = %v", result, err)
	}

	dpr.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(2)))
	if _, err := base.ValidateDPR(dpr); err == nil {
		t.Fatal("accepted duplicate Disconnect-Cause")
	}
}
