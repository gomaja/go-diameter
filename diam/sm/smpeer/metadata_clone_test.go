package smpeer

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func TestMetadataCloneOwnsCapabilitiesAndNestedAVPs(t *testing.T) {
	address := datatype.Address{Family: datatype.AddressFamilyIPv4, Value: []byte{1, 2, 3, 4}}
	inner := diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(42))
	group := diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{inner}})
	metadata := &Metadata{
		OriginHost: "peer.example.net", OriginRealm: "example.net", Applications: []uint32{4, 5},
		CER: &smparser.CER{
			OriginHost: "peer.example.net", OriginRealm: "example.net",
			OriginStateID:               diam.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(7)),
			InbandSecurityID:            diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, address),
			VendorSpecificApplicationID: []*diam.AVP{group},
		},
	}
	copy := metadata.Clone()
	if copy == metadata || copy.CER == metadata.CER {
		t.Fatal("clone retains metadata or CER pointer")
	}
	copy.Applications[0] = 99
	copy.CER.OriginStateID.Data = datatype.Unsigned32(88)
	copy.CER.InbandSecurityID.Data.(datatype.Address).Value[0] = 99
	copy.CER.VendorSpecificApplicationID[0].Data.(*diam.GroupedAVP).AVP[0].Data = datatype.Unsigned32(99)
	if metadata.Applications[0] != 4 || metadata.CER.OriginStateID.Data != datatype.Unsigned32(7) || address.Value[0] != 1 || inner.Data != datatype.Unsigned32(42) {
		t.Fatal("clone shares mutable capability data")
	}
	if (*Metadata)(nil).Clone() != nil {
		t.Fatal("nil clone is non-nil")
	}
}

func TestMetadataCloneOwnsCEAFields(t *testing.T) {
	original := &Metadata{CEA: &smparser.CEA{
		OriginHost: "peer.example.net", SupportedVendorID: []*diam.AVP{diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(42))},
		FailedAVP: []*diam.AVP{diam.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("bad"))}})},
	}}
	copy := original.Clone()
	copy.CEA.SupportedVendorID[0].Data = datatype.Unsigned32(99)
	copy.CEA.FailedAVP[0].Data.(*diam.GroupedAVP).AVP[0].Data = datatype.DiameterIdentity("changed")
	if original.CEA.SupportedVendorID[0].Data != datatype.Unsigned32(42) || original.CEA.FailedAVP[0].Data.(*diam.GroupedAVP).AVP[0].Data != datatype.DiameterIdentity("bad") {
		t.Fatal("clone shares CEA AVPs")
	}
}

func TestMetadataCloneOwnsParsedApplicationIDs(t *testing.T) {
	request := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, dict.Default)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.OriginHost, datatype.DiameterIdentity("peer.example.net")},
		{avp.OriginRealm, datatype.DiameterIdentity("example.net")},
		{avp.AuthApplicationID, datatype.Unsigned32(0xffffffff)},
	} {
		if _, err := request.NewAVP(field.code, avp.Mbit, 0, field.value); err != nil {
			t.Fatal(err)
		}
	}
	cer := new(smparser.CER)
	if _, err := cer.Parse(request, smparser.Server); err != nil {
		t.Fatal(err)
	}
	original := FromCER(cer)
	copy := original.Clone()
	copy.CER.Applications()[0] = 5
	copy.Applications[0] = 6
	if original.CER.Applications()[0] != 0xffffffff || original.Applications[0] != 0xffffffff {
		t.Fatal("clone shares parsed application IDs")
	}
}
