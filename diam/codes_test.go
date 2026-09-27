package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestResultCodeValuesOnWire(t *testing.T) {
	// RFC 6733 §7.1, RFC 8506 §9.2, and IANA Result-Code AVP Values.
	for _, tc := range []struct {
		name        string
		value, want uint32
	}{
		{"MultiRoundAuth", MultiRoundAuth, 1001},
		{"Success", Success, 2001},
		{"LimitedSuccess", LimitedSuccess, 2002},
		{"CommandUnsupported", CommandUnsupported, 3001},
		{"UnableToDeliver", UnableToDeliver, 3002},
		{"RealmNotServed", RealmNotServed, 3003},
		{"TooBusy", TooBusy, 3004},
		{"LoopDetected", LoopDetected, 3005},
		{"RedirectIndication", RedirectIndication, 3006},
		{"ApplicationUnsupported", ApplicationUnsupported, 3007},
		{"InvalidHDRBits", InvalidHDRBits, 3008},
		{"InvalidAVPBits", InvalidAVPBits, 3009},
		{"UnknownPeer", UnknownPeer, 3010},
		{"AuthenticationRejected", AuthenticationRejected, 4001},
		{"OutOfSpace", OutOfSpace, 4002},
		{"ElectionLost", ElectionLost, 4003},
		{"AVPUnsupported", AVPUnsupported, 5001},
		{"UnknownUser", UnknownUser, 5030},
		{"UnknownSessionID", UnknownSessionID, 5002},
		{"AuthorizationRejected", AuthorizationRejected, 5003},
		{"InvalidAVPValue", InvalidAVPValue, 5004},
		{"MissingAVP", MissingAVP, 5005},
		{"ResourcesExceeded", ResourcesExceeded, 5006},
		{"ContradictingAVPs", ContradictingAVPs, 5007},
		{"AVPNotAllowed", AVPNotAllowed, 5008},
		{"AVPOccursTooManyTimes", AVPOccursTooManyTimes, 5009},
		{"NoCommonApplication", NoCommonApplication, 5010},
		{"UnsupportedVersion", UnsupportedVersion, 5011},
		{"UnableToComply", UnableToComply, 5012},
		{"InvalidBitInHeader", InvalidBitInHeader, 5013},
		{"InvalidAVPLength", InvalidAVPLength, 5014},
		{"InvalidAVPLenght", InvalidAVPLenght, 5014},
		{"InvalidMessageLength", InvalidMessageLength, 5015},
		{"InvalidAVPBitCombo", InvalidAVPBitCombo, 5016},
		{"NoCommonSecurity", NoCommonSecurity, 5017},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := NewRequest(CapabilitiesExchange, 0, dict.Default).Answer(tc.value)
			var wire bytes.Buffer
			if _, err := answer.WriteTo(&wire); err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadMessage(&wire, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			result, err := decoded.FindAVP(avp.ResultCode, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := uint32(result.Data.(datatype.Unsigned32)); got != tc.want {
				t.Fatalf("wire Result-Code = %d, want %d", got, tc.want)
			}
		})
	}
}
