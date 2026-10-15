package protocol

import (
	"slices"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// RFC 6733 §§5.3,6.11: retain the parser's recognized offer separately from
// the complete remote advertisement and the negotiated intersection.
func TestCandidateParsedApplicationsPreserveOrderAndIsolation(t *testing.T) {
	c := machine(t, func(cfg *Config) {
		cfg.Local.AuthApplicationID = append(cfg.Local.AuthApplicationID, diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(8)))
		cfg.Local.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(3))}
	})
	m := cer(t)
	for _, offer := range []struct{ code, id uint32 }{
		{avp.AcctApplicationID, 3}, {avp.AuthApplicationID, 999}, {avp.AuthApplicationID, 8}, {avp.AuthApplicationID, 4},
	} {
		m.AddAVP(diam.NewAVP(offer.code, avp.Mbit, 0, datatype.Unsigned32(offer.id)))
	}
	m.AddAVP(diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(10415)),
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
	}}))
	candidate := find(t, c.Handle(receive(m)), ValidatedCER)
	caps := candidate.Snapshot.Capabilities()
	want := []uint32{3, 4, 8, 4, 4}
	if !slices.Equal(caps.ParsedApplications, want) {
		t.Fatalf("parsed applications=%v want=%v", caps.ParsedApplications, want)
	}
	if !slices.Contains(caps.RemoteApplications, 999) || slices.Contains(caps.ParsedApplications, 999) {
		t.Fatalf("remote offer=%v parsed=%v", caps.RemoteApplications, caps.ParsedApplications)
	}
	caps.ParsedApplications[0] = 999
	if !slices.Equal(candidate.Snapshot.Capabilities().ParsedApplications, want) {
		t.Fatal("capabilities getter aliases the stored snapshot")
	}
	in := event(Activate)
	in.Token = candidate.Token
	published := find(t, c.Handle(in), Publish)
	if !slices.Equal(published.Snapshot.Capabilities().ParsedApplications, want) {
		t.Fatal("candidate mutation affected published capabilities")
	}
	c.caps.ParsedApplications[0] = 8
	if !slices.Equal(candidate.Snapshot.Capabilities().ParsedApplications, want) || !slices.Equal(published.Snapshot.Capabilities().ParsedApplications, want) {
		t.Fatal("core mutation affected existing snapshots")
	}
}
