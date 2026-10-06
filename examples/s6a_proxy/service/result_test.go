package service

import (
	"strings"
	"testing"
)

func TestBaseResultNamespaceAndClass(t *testing.T) {
	// RFC 6733 section 7.1 classifies every 2xxx result as success.
	for _, code := range []uint32{0, 2000, 2001, 2002, 2999} {
		if err := TranslateBaseDiamResultCode(code); err != nil {
			t.Errorf("%d: %v", code, err)
		}
	}
	for code, name := range map[uint32]string{1999: "BASE_DIAMETER", 3000: "BASE_DIAMETER", 3001: "COMMAND_UNSUPPORTED", 3008: "INVALID_HDR_BITS", 5001: "AVP_UNSUPPORTED", 5004: "INVALID_AVP_VALUE"} {
		err := TranslateBaseDiamResultCode(code)
		if err == nil || !strings.Contains(err.Error(), "("+name+")") {
			t.Errorf("%d: %v, want %s", code, err, name)
		}
	}
}
