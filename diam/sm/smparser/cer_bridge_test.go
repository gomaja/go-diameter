package smparser

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/internal/parserbridge"
)

// Package sm reaches the conversion only through parserbridge.
func TestFromValidatedCERInstalled(t *testing.T) {
	if _, ok := parserbridge.FromValidatedCER.(func(*base.CER, []uint32) *CER); !ok {
		t.Fatalf("parserbridge.FromValidatedCER = %T", parserbridge.FromValidatedCER)
	}
}

// RFC 6733 §§5.3.1,6.11: preserve the validated fields and parser's ordered,
// locally recognized application list when publishing accepted-peer metadata.
func TestFromValidatedCERDetachedFields(t *testing.T) {
	id := func(code, value uint32) *diam.AVP {
		return diam.NewAVP(code, avp.Mbit, 0, datatype.Unsigned32(value))
	}
	source := &base.CER{
		OriginHost: "peer.example", OriginRealm: "example",
		HostIPAddresses: []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("192.0.2.1"))},
		OriginStateID:   id(avp.OriginStateID, 9), InbandSecurityID: id(avp.InbandSecurityID, 0),
		AcctApplicationID:           []*diam.AVP{id(avp.AcctApplicationID, 3)},
		AuthApplicationID:           []*diam.AVP{id(avp.AuthApplicationID, 4)},
		VendorSpecificApplicationID: []*diam.AVP{diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{id(avp.VendorID, 10415), id(avp.AuthApplicationID, 4)}})},
	}
	apps := []uint32{3, 4, 4, 0xffffffff}
	got := fromValidatedCER(source, apps)
	want := &CER{
		OriginHost: source.OriginHost, OriginRealm: source.OriginRealm,
		HostIPAddresses: source.HostIPAddresses, OriginStateID: source.OriginStateID,
		InbandSecurityID: source.InbandSecurityID, AcctApplicationID: source.AcctApplicationID,
		AuthApplicationID: source.AuthApplicationID, VendorSpecificApplicationID: source.VendorSpecificApplicationID,
		appID: apps,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("converted CER=%+v want=%+v", got, want)
	}
	pristine := got.Clone()
	got.OriginHost = "mutated.example"
	got.OriginRealm = "mutated"
	got.HostIPAddresses[0] = datatype.AddressFromIP(netip.MustParseAddr("192.0.2.2"))
	got.OriginStateID.Data = datatype.Unsigned32(10)
	got.InbandSecurityID.Data = datatype.Unsigned32(1)
	got.AcctApplicationID[0].Data = datatype.Unsigned32(30)
	got.AuthApplicationID[0].Data = datatype.Unsigned32(40)
	got.VendorSpecificApplicationID[0].Data.(*diam.GroupedAVP).AVP[0].Data = datatype.Unsigned32(99)
	got.Applications()[0] = 99
	if fresh := fromValidatedCER(source, apps); !reflect.DeepEqual(fresh, pristine) {
		t.Fatalf("conversion aliases source: fresh=%+v want=%+v", fresh, pristine)
	}
	// The clone must also detach the private application cache.
	cloned := pristine.Clone()
	cloned.Applications()[0] = 100
	if pristine.Applications()[0] != 3 {
		t.Fatal("Clone aliases the preserved application list")
	}
}

func TestFromValidatedCERNilAndEmpty(t *testing.T) {
	if got := fromValidatedCER(nil, []uint32{4}); got != nil {
		t.Fatalf("nil source produced %+v", got)
	}
	for _, ids := range [][]uint32{nil, {}} {
		got := fromValidatedCER(&base.CER{}, ids)
		if got == nil || !reflect.DeepEqual(got.Applications(), ids) {
			t.Fatalf("application list=%v want=%v (including nilness)", got, ids)
		}
	}
}
