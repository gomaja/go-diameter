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

func TestCERAndDWRAnswersCopyIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hop, end uint32
	}{
		{"zero", 0, 0}, {"nonzero", 71, 72},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := New(serverSettings)
			srv := diamtest.NewServer(sm, dict.Default)
			defer srv.Close()
			answers := make(chan *diam.Message, 2)
			mux := diam.NewServeMux()
			mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { answers <- m })
			mux.HandleFunc("DWA", func(_ diam.Conn, m *diam.Message) { answers <- m })
			cli, err := diam.Dial(srv.Addr, mux, dict.Default)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			cer := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
			cer.Header.HopByHopID, cer.Header.EndToEndID = tc.hop, tc.end
			mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
			mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
			mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
			mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
			mustSMClientAVP(t, cer, avp.ProductName, 0, 0, clientSettings.ProductName)
			mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
			if _, err := cer.WriteTo(cli); err != nil {
				t.Fatal(err)
			}
			check := func(command uint32) {
				t.Helper()
				select {
				case m := <-answers:
					if m.Header.CommandCode != command || m.Header.HopByHopID != tc.hop || m.Header.EndToEndID != tc.end {
						t.Fatalf("answer command/IDs = (%d,%d,%d), want (%d,%d,%d)", m.Header.CommandCode, m.Header.HopByHopID, m.Header.EndToEndID, command, tc.hop, tc.end)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("no answer")
				}
			}
			check(diam.CapabilitiesExchange)
			dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
			dwr.Header.HopByHopID, dwr.Header.EndToEndID = tc.hop, tc.end
			mustSMClientAVP(t, dwr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
			mustSMClientAVP(t, dwr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
			if _, err := dwr.WriteTo(cli); err != nil {
				t.Fatal(err)
			}
			check(diam.DeviceWatchdog)
		})
	}
}
