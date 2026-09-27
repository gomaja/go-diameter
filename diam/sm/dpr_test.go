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

func dialHandshakeForDPR(t *testing.T, handler diam.Handler, addr string) diam.Conn {
	t.Helper()
	answers := make(chan *diam.Message, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(_ diam.Conn, m *diam.Message) { answers <- m })
	if handler != nil {
		mux.HandleFunc("DPA", handler.ServeDIAM)
	}
	c, err := diam.Dial(addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	cer := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
	mustSMClientAVP(t, cer, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, cer, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, cer, avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	mustSMClientAVP(t, cer, avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	mustSMClientAVP(t, cer, avp.ProductName, 0, 0, clientSettings.ProductName)
	mustSMClientAVP(t, cer, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	if _, err := cer.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-answers:
		if !testResultCode(a, diam.Success) {
			t.Fatalf("CEA result: %s", a)
		}
	case <-time.After(time.Second):
		t.Fatal("no CEA")
	}
	return c
}

func TestPeerDPRAnsweredAndWaitsForPeerClose(t *testing.T) {
	cfg := *serverSettings
	cfg.DPRCloseTimeout = 80 * time.Millisecond
	causes := make(chan DisconnectCause, 1)
	cfg.OnDPR = func(_ diam.Conn, cause DisconnectCause) { causes <- cause }
	sm := New(&cfg)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	answers := make(chan *diam.Message, 1)
	c := dialHandshakeForDPR(t, diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) { answers <- m }), srv.Addr)
	peer := <-sm.HandshakeNotify()
	dpr := diam.NewRequest(diam.DisconnectPeer, 0, dict.Default)
	mustSMClientAVP(t, dpr, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, dpr, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, dpr, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	if _, err := dpr.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-answers:
		if a.Header.HopByHopID != dpr.Header.HopByHopID || !testResultCode(a, diam.Success) {
			t.Fatalf("DPA mismatch: %s", a)
		}
		for _, code := range []uint32{avp.OriginHost, avp.OriginRealm} {
			if _, err := a.FindAVP(code, 0); err != nil {
				t.Fatalf("DPA missing AVP %d: %v", code, err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no DPA")
	}
	select {
	case <-peer.(diam.CloseNotifier).CloseNotify():
		t.Fatal("peer closed transport before initiator")
	case <-time.After(30 * time.Millisecond):
	}
	select {
	case cause := <-causes:
		if cause != DisconnectRebooting {
			t.Fatalf("cause = %d", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("OnDPR was not called")
	}
	select {
	case <-peer.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("Closing state did not time out")
	}
}

func TestValidateDPRRequiredAVPs(t *testing.T) {
	makeDPR := func() *diam.Message {
		m := diam.NewRequest(diam.DisconnectPeer, 0, dict.Default)
		mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
		mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
		return m
	}
	for _, tc := range []struct {
		name string
		edit func(*diam.Message)
	}{
		{"missing cause", func(*diam.Message) {}},
		{"duplicate cause", func(m *diam.Message) {
			mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(1))
			mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(2))
		}},
		{"invalid cause", func(m *diam.Message) {
			mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(9))
		}},
		{"missing host", func(m *diam.Message) {
			m.AVP = m.AVP[1:]
			mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := makeDPR()
			tc.edit(m)
			if _, err := validateDPR(m); err == nil {
				t.Fatal("accepted invalid DPR")
			}
		})
	}
}

func TestPeerDPRBeforeHandshakeGetsNoDPA(t *testing.T) {
	sm := New(serverSettings)
	srv := diamtest.NewServer(sm, dict.Default)
	defer srv.Close()
	answers := make(chan *diam.Message, 1)
	mux := diam.NewServeMux()
	mux.HandleFunc("DPA", func(_ diam.Conn, m *diam.Message) { answers <- m })
	c, err := diam.Dial(srv.Addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := diam.NewRequest(diam.DisconnectPeer, 0, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	mustSMClientAVP(t, m, avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0))
	if _, err := m.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	select {
	case <-answers:
		t.Fatal("DPA sent before CER/CEA")
	case <-time.After(50 * time.Millisecond):
	}
}
