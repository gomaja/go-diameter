package diam

import (
	"errors"
	"fmt"
	"testing"
)

func TestProtocolErrorClassification(t *testing.T) {
	for _, kind := range []ProtocolErrorKind{
		ProtocolMalformedMessage, ProtocolInvalidHeader, ProtocolUnsupportedAVP,
		ProtocolInvalidRequest, ProtocolUnsupportedCommand, ProtocolUnsupportedApplication,
		ProtocolInvalidDWR, ProtocolInvalidDWA, ProtocolRejectedDWA, ProtocolInvalidDPR,
		ProtocolInvalidDPA, ProtocolUnexpectedMessage, ProtocolHandshakeState,
		ProtocolCERRejected, ProtocolHandshakeTimeout, ProtocolCEARejected,
		ProtocolPeerRejected, ProtocolDisconnectTimeout, ProtocolWatchdogTimeout,
	} {
		t.Run(string(kind), func(t *testing.T) {
			original := NewProtocolError(kind, 5004)
			err := fmt.Errorf("application: %w", original)
			var got *ProtocolError
			if !errors.As(err, &got) || got != original || got.ResultCode() != 5004 || got.Kind() != kind {
				t.Fatalf("classification lost: %v", err)
			}
			if !errors.Is(err, kind) || errors.Is(err, ProtocolErrorKind("unrelated")) {
				t.Fatalf("kind matching lost: %v", err)
			}
			if got.Error() == "" || kind.Error() == "" {
				t.Fatal("classification has no diagnostic description")
			}
		})
	}
}
