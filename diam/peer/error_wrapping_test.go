package peer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

func TestSendPreservesDecoderError(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, m, nil)
	msg := outboundRequest("", "example.net")
	msg.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown{1, 2}))
	_, err = m.Send(context.Background(), msg)
	var me *diam.MessageError
	if !errors.Is(err, ErrInvalidRequest) || !errors.As(err, &me) || me.ResultCode != diam.InvalidAVPLength {
		t.Fatalf("Send lost decoder cause: %v", err)
	}
}

func TestControlBuildErrorsPreserveCause(t *testing.T) {
	for _, kind := range []psmEvent{iAck, iDWR, stop} {
		t.Run(string(kind), func(t *testing.T) {
			reports := make(chan PeerEvent, 8)
			m, err := New(Config{Settings: testSettings("local.example.net"), OnPeerEvent: func(e PeerEvent) { reports <- e }})
			if err != nil {
				t.Fatal(err)
			}
			defer closeManager(t, m, nil)
			// Inject invalid local address data after configuration validation.
			m.cfg.Settings.HostIPAddresses = []datatype.Address{{}}
			c := newFakeConn()
			defer c.Close()
			s := &session{m: m, c: c, writes: make(chan writeRequest, 8), closed: make(chan struct{})}
			a := &actor{m: m, cfg: PeerConfig{Host: "known.example.net", NoAutoReconnect: true}, state: IOpen, i: s, active: s, events: make(chan event, 8)}
			if kind == iAck {
				a.state = WaitConnAck
			}
			msg := diam.NewRequest(diam.DeviceWatchdog, 0, dict.New())
			if kind != iAck {
				for len(s.writes) < cap(s.writes) {
					s.writes <- writeRequest{msg: msg}
				}
			}
			a.step(kind, s, msg)
			select {
			case e := <-reports:
				if e.Reason == nil || kind == iAck && errors.Unwrap(e.Reason) == nil || kind != iAck && !strings.Contains(e.Reason.Error(), "queue full") {
					t.Fatalf("%s lost cause: %v", kind, e.Reason)
				}
			case <-time.After(time.Second):
				t.Fatal("missing failure")
			}
		})
	}
}
