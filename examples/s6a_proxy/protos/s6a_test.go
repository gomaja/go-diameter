package protos

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestExperimentalResults(t *testing.T) {
	// 3GPP TS 29.272 V19.6.0 sections 7.4.3 and 7.4.4.
	want := map[string]int32{"UNDEFINED": 0, "USER_UNKNOWN": 5001,
		"UNKNOWN_EPS_SUBSCRIPTION": 5420, "RAT_NOT_ALLOWED": 5421,
		"ROAMING_NOT_ALLOWED": 5004, "EQUIPMENT_UNKNOWN": 5422,
		"UNKNOWN_SERVING_NODE": 5423, "AUTHENTICATION_DATA_UNAVAILABLE": 4181,
		"CAMEL_SUBSCRIPTION_PRESENT": 4182}
	if len(ErrorCode_value) != len(want) {
		t.Fatalf("experimental values: %v", ErrorCode_value)
	}
	for name, value := range want {
		if got, ok := ErrorCode_value[name]; !ok || got != value {
			t.Errorf("%s = %d, present %v; want %d", name, got, ok, value)
		}
	}
	// The same wire number has different meanings in the two namespaces.
	if BaseResultCode(5001).String() != "AVP_UNSUPPORTED" || ErrorCode(5001).String() != "USER_UNKNOWN" {
		t.Fatal("result namespaces conflated")
	}
	if BaseResultCode(3001).String() != "COMMAND_UNSUPPORTED" || BaseResultCode(3008).String() != "INVALID_HDR_BITS" {
		t.Fatal("incorrect base result names")
	}
	// TS 29.272 V19.6.0 section 7.3.24.
	if CancelLocationRequest_CancellationType(5).String() != "DISASTER_CONDITION_TERMINATED" {
		t.Fatal("missing cancellation type")
	}
}

func TestModernProtoRoundTrip(t *testing.T) {
	want := &AuthenticationInformationAnswer{ErrorCode: ErrorCode_CAMEL_SUBSCRIPTION_PRESENT,
		EutranVectors: []*AuthenticationInformationAnswer_EUTRANVector{{Rand: []byte{1, 2}, Xres: []byte{3}, Autn: []byte{4}, Kasme: []byte{5}}}}
	data, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got := new(AuthenticationInformationAnswer)
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("round trip: %v, want %v", got, want)
	}
}
