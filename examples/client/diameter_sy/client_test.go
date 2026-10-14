package main

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/sy"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// TS 29.219 V19.0.0 §§5.3.0, 5.3.4, 5.6.2: SLR requires the application
// identifier and a vendor-specific Enumerated SL-Request-Type.
func TestInitialSLRRoundTrip(t *testing.T) {
	dictionary, err := dict.New(sy.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &sm.Settings{Dict: dictionary, OriginHost: "pcrf.example.org", OriginRealm: "example.org"}
	meta := &smpeer.Metadata{OriginHost: "ocs.example.org", OriginRealm: "example.org"}
	m, err := newSLR(cfg, meta)
	if err != nil {
		t.Fatal(err)
	}
	if m.Dictionary() != dictionary {
		t.Fatal("request lost selected parser")
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var wire bytes.Buffer
	if _, err := m.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(&wire, dictionary)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded Validate: %v", err)
	}
	if decoded.Header.ApplicationID != 16777302 || decoded.Header.CommandCode != 8388635 || decoded.Header.CommandFlags != diam.RequestFlag|diam.ProxiableFlag {
		t.Fatalf("unexpected SLR header: %+v", decoded.Header)
	}
	requestType, err := decoded.FindAVP(avp.SLRequestType, 10415)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := requestType.Data.(datatype.Enumerated); !ok || got != 0 || requestType.Flags != avp.Mbit|avp.Vbit {
		t.Fatalf("SL-Request-Type = %+v", requestType)
	}
	app, err := decoded.FindAVP(avp.AuthApplicationID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := app.Data.(datatype.Unsigned32); !ok || got != 16777302 {
		t.Fatalf("Auth-Application-Id = %+v", app)
	}
	subscription, err := decoded.FindAVP(avp.SubscriptionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	group, ok := subscription.Data.(*diam.GroupedAVP)
	if !ok || subscription.Flags != avp.Mbit || len(group.AVP) != 2 {
		t.Fatalf("Subscription-Id = %+v", subscription)
	}
	for _, child := range group.AVP {
		if child.VendorID != 0 || child.Flags != avp.Mbit {
			t.Fatalf("subscription member = %+v", child)
		}
	}
	if group.AVP[0].Code != avp.SubscriptionIDType || group.AVP[0].Data != datatype.Enumerated(3) || group.AVP[1].Code != avp.SubscriptionIDData || group.AVP[1].Data != datatype.UTF8String("subscriber@example.org") {
		t.Fatalf("subscription members = %+v", group.AVP)
	}
}
