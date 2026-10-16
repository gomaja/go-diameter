package protocol

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestRequiredReplyBuildFailureRetainsCause(t *testing.T) {
	c := machine(t, func(cfg *Config) { cfg.Local.HostIPAddresses = []datatype.Address{{}} })
	c.Handle(event(Start))
	candidate := find(t, c.Handle(receive(cer(t))), ValidatedCER)
	in := event(Activate)
	in.Token = candidate.Token
	var n Notification
	for _, e := range c.Handle(in) {
		if e.Kind == Notify && e.Notification.Protocol == diam.ProtocolReplyFailure {
			n = e.Notification
		}
	}
	if n.CauseError == nil {
		t.Fatal("required reply builder failure lost its original error")
	}
}

func TestRejectionBuildFailureRetainsTypedBuilderCause(t *testing.T) {
	for _, open := range []bool{false, true} {
		t.Run(fmt.Sprintf("open=%t", open), func(t *testing.T) {
			cfg := func(cfg *Config) {
				cfg.PreserveReplyErrorFormatWrapper = true
				cfg.ReaderOwnsMessageErrorClosure = true
				cfg.RejectFatalRepeatedCER = true
			}
			c := machine(t, cfg)
			if open {
				c = opened(t, cfg)
			} else {
				c.Handle(event(Start))
			}
			dictionary, err := dict.NewParser()
			if err != nil {
				t.Fatal(err)
			}
			in := receive(diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dictionary))
			in.ErrorInput = true
			in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPLength, Fatal: true}
			var n Notification
			for _, e := range c.Handle(in) {
				if e.Kind == Notify && e.Notification.Protocol != "" {
					n = e.Notification
				}
			}
			if n.Reply != diam.ProtocolReplyFailed || n.ReplyCode != diam.InvalidAVPLength || !n.Closing || n.ReplyError == nil {
				t.Fatalf("lost rejected exchange or builder failure: %+v", n)
			}
			if reflect.TypeOf(n.ReplyError) != handshakeFmtWrapType || !strings.Contains(n.ReplyError.Error(), "cannot form valid Diameter error answer") {
				t.Fatalf("builder error changed: %T %v", n.ReplyError, n.ReplyError)
			}
		})
	}
}

func TestCopiedStandardWrapperRetainsTypeAndDetachesEvidence(t *testing.T) {
	failed := diam.NewAVP(1, 0, 0, datatype.Unknown{1, 2})
	validation := &diam.ValidationError{ResultCode: diam.InvalidAVPLength, FailedAVP: failed}
	original := fmt.Errorf("before: %w: after", validation)
	if defaultCopy := copyHandshakeError(original); reflect.TypeOf(defaultCopy) == reflect.TypeOf(original) || defaultCopy.Error() != original.Error() {
		t.Fatalf("default wrapper diagnostic changed: %T %v", defaultCopy, defaultCopy)
	}
	copied := copyHandshakeError(original, true)
	if reflect.TypeOf(copied) != reflect.TypeOf(original) || copied.Error() != original.Error() {
		t.Fatalf("copied wrapper changed type/text: %T %v", copied, copied)
	}
	var evidence *diam.ValidationError
	if !errors.As(copied, &evidence) || evidence == validation || evidence.FailedAVP == failed {
		t.Fatal("wrapper retained mutable parser evidence")
	}
	for range 100 {
		original = fmt.Errorf("wrapped: %w", original)
	}
	if bounded := copyHandshakeError(original, true); !strings.Contains(bounded.Error(), "traversal limit") {
		t.Fatal("standard wrappers bypassed the error traversal bound")
	}
}
