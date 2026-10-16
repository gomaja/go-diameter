package protocol

import (
	"fmt"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestRejectedMessageRetainsOriginalEvidence(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(fmt.Sprintf("closing=%t", closing), func(t *testing.T) {
			c := opened(t)
			if closing {
				c.Handle(event(Disconnect))
			}
			before := c.Snapshot().Timer(ClosingTimer)
			empty, err := dict.NewParser()
			if err != nil {
				t.Fatal(err)
			}
			in := receive(diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 1, 2, empty))
			failed := diam.NewAVP(1, 0, 0, datatype.Unknown{1, 2})
			original := &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: failed}
			notice := find(t, c.reject(nil, in, diam.ProtocolInvalidRequest, original), Notify).Notification
			copied, ok := notice.CauseError.(*diam.MessageError)
			if !ok || copied == original || copied.ResultCode != original.ResultCode || copied.FailedAVP == failed {
				t.Fatalf("rejection lost detached typed evidence: %T %#v", notice.CauseError, notice.CauseError)
			}
			failed.Data.(datatype.Unknown)[0] = 9
			if copied.FailedAVP.Data.(datatype.Unknown)[0] != 1 {
				t.Fatal("rejection retained mutable failed AVP")
			}
			if closing {
				if c.Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != before || notice.Reply != diam.ProtocolReplyNone {
					t.Fatalf("Closing rejection changed lifecycle or selected a reply: %+v", notice)
				}
			} else if notice.Reply != diam.ProtocolReplyFailed || notice.ReplyError == nil || c.Phase() != Closed {
				t.Fatalf("builder failure lost its distinct outcome: %+v", notice)
			}
		})
	}
}

func TestClosingRequestRejectionSkipsAnswerConstruction(t *testing.T) {
	c := opened(t)
	c.Handle(event(Disconnect))
	before := c.Snapshot().Timer(ClosingTimer)
	empty, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	in := receive(diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 1, 2, empty))
	es := c.requestError(nil, in, &base.RequestError{Kind: diam.ProtocolUnsupportedAVP, Code: diam.AVPUnsupported})
	var notice Notification
	for _, e := range es {
		if e.Kind == Notify && e.Notification.Protocol != "" {
			notice = e.Notification
		}
	}
	if c.Phase() != Closing || c.Snapshot().Timer(ClosingTimer) != before || notice.Protocol != diam.ProtocolUnsupportedAVP || notice.ResultCode != diam.AVPUnsupported || notice.Reply != diam.ProtocolReplyNone {
		t.Fatalf("Closing rejection attempted a failing answer build: phase=%v notice=%+v", c.Phase(), notice)
	}
	for _, e := range es {
		if e.Kind != Notify && e.Kind != Discard {
			t.Fatalf("Closing rejection selected work: %v", e.Kind)
		}
	}
}
