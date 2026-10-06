package base

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestRebuildAnswerAVPNestedValues(t *testing.T) {
	dictionary := dict.Default
	leaf := diam.NewAVP(avp.PublicIdentity, avp.Pbit|0x1f, 10415, datatype.UTF8String("sip:user@example.net"))
	unknown := diam.NewAVP(0xffffff, 0x3f, 99999, datatype.Unknown("extension"))
	inner := diam.NewAVP(avp.VendorSpecificApplicationID, 0, 0, &diam.GroupedAVP{AVP: []*diam.AVP{leaf, unknown}})
	outer := diam.NewAVP(avp.VendorSpecificApplicationID, 0x1f, 0, &diam.GroupedAVP{AVP: []*diam.AVP{inner}})
	rebuilt := rebuildAnswerAVP(outer, diam.TGPP_CX_APP_ID, dictionary, dictionary.Snapshot(), 0)
	if rebuilt == nil {
		t.Fatal("could not rebuild nested values")
	}
	nested := rebuilt.Data.(*diam.GroupedAVP).AVP[0]
	children := nested.Data.(*diam.GroupedAVP).AVP
	if rebuilt.Flags != avp.Mbit || nested.Flags != avp.Mbit || children[0].Flags != avp.Mbit|avp.Vbit || children[1].Flags != avp.Vbit {
		t.Fatalf("rebuilt flags: outer %02x, inner %02x, known %02x, unknown %02x", rebuilt.Flags, nested.Flags, children[0].Flags, children[1].Flags)
	}
	if children[0].Data != leaf.Data || string(children[1].Data.(datatype.Unknown)) != "extension" {
		t.Fatal("values changed")
	}
	if leaf.Flags != avp.Vbit|avp.Pbit|0x1f || unknown.Flags != avp.Vbit|0x3f {
		t.Fatal("request modified")
	}
}

func TestRebuildAnswerAVPUnusableValues(t *testing.T) {
	cycle := &diam.GroupedAVP{}
	cyclic := &diam.AVP{Code: avp.VendorSpecificApplicationID, Data: cycle}
	cycle.AVP = []*diam.AVP{cyclic}
	for name, received := range map[string]*diam.AVP{
		"nil":          nil,
		"nil-data":     {Code: avp.VendorID},
		"undecoded":    diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unknown{0}),
		"nil-group":    {Code: avp.VendorSpecificApplicationID, Data: (*diam.GroupedAVP)(nil)},
		"broken-group": diam.NewAVP(avp.VendorSpecificApplicationID, 0, 0, datatype.Grouped{1}),
		"nil-child":    {Code: avp.VendorSpecificApplicationID, Data: &diam.GroupedAVP{AVP: []*diam.AVP{nil}}},
		"cycle":        cyclic,
	} {
		t.Run(name, func(t *testing.T) {
			if got := rebuildAnswerAVP(received, diam.TGPP_CX_APP_ID, dict.Default, dict.Default.Snapshot(), 0); got != nil {
				t.Fatalf("unusable value rebuilt as %v", got)
			}
		})
	}
}

func TestRebuildAnswerAVPEvidence(t *testing.T) {
	evidence := diam.NewAVP(avp.VendorID, 0x1f, 0, datatype.Unknown{1})
	failed := diam.NewAVP(avp.FailedAVP, 0x1f, 0, &diam.GroupedAVP{AVP: []*diam.AVP{evidence}})
	rebuilt := rebuildAnswerAVP(failed, 0, dict.Default, dict.Default.Snapshot(), 0)
	if rebuilt == nil || rebuilt.Flags != avp.Mbit || rebuilt.Data != failed.Data {
		t.Fatalf("evidence changed: %v", rebuilt)
	}
	for _, group := range []*diam.GroupedAVP{nil, {AVP: []*diam.AVP{nil}}, {}} {
		bad := &diam.AVP{Code: avp.FailedAVP, Data: group}
		if group != nil && len(group.AVP) == 0 {
			group.AVP = []*diam.AVP{bad}
		}
		if rebuilt := rebuildAnswerAVP(bad, 0, dict.Default, dict.Default.Snapshot(), 0); rebuilt != nil {
			t.Fatal("accepted malformed evidence tree")
		}
	}
}
