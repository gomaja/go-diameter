package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestCEAOriginStateIDBelongsToServer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state datatype.Unsigned32
		app   datatype.Unsigned32
	}{
		{"success-set", 222, 1001},
		{"success-unset", 0, 1001},
		{"error-set", 222, 1000},
		{"error-unset", 0, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := *serverSettings
			settings.OriginStateID = tc.state
			sm := mustNewStateMachine(t, &settings)
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			answers := make(chan *diam.Message, 1)
			mux := diam.NewServeMux()
			mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { answers <- m })
			cli, err := diam.Dial(srv.Addr, mux, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			m := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
			mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
			mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
			mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
			mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
			mustSMClientAVP(t, m, avp.ProductName, 0, 0, clientSettings.ProductName)
			mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(111))
			mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, tc.app)
			if _, err := m.WriteTo(cli); err != nil {
				t.Fatal(err)
			}
			select {
			case answer := <-answers:
				a, err := answer.FindAVP(avp.OriginStateID, 0)
				if tc.state == 0 {
					if err == nil {
						t.Fatalf("unexpected Origin-State-Id %v", a.Data)
					}
				} else if err != nil || a.Data.(datatype.Unsigned32) != tc.state {
					t.Fatalf("Origin-State-Id = %v, error = %v; want %d", a, err, tc.state)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no CEA")
			}
		})
	}
}
