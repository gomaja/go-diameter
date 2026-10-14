package dict_test

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
	"github.com/gomaja/go-diameter/diam/dict/rx"
	"github.com/gomaja/go-diameter/diam/dict/sh"
)

// The selection deliberately excludes S6c/S6a/SWx: Cx builds on NASREQ and
// Base, and Sh builds on Cx. TS 29.229 V19.1.0 §6.3.41; TS 29.329 V19.1.0 §6.3.
func TestCxShBundledSelection(t *testing.T) {
	for i, selection := range [][]dict.Dictionary{{cx.Dictionary(), nasreq.Dictionary(), dict.Base()}, {sh.Dictionary(), cx.Dictionary(), nasreq.Dictionary(), dict.Base()}} {
		d := newTestParser(t, selection...)
		appID := uint32(16777216)
		if i == 1 {
			appID = 16777217
		}
		app, err := d.App(appID)
		if err != nil {
			t.Fatal(err)
		}
		check := func(rules []*dict.Rule) {
			for _, r := range rules {
				if r.AVP != "AVP" {
					if _, err := d.FindAVPByName(appID, r.AVP); err != nil {
						t.Errorf("application %d: %v", appID, err)
					}
				}
			}
		}
		for _, c := range app.Command {
			check(c.Request.Rule)
			check(c.Answer.Rule)
		}
		for idx, a := range dict.NameIndexForTesting(d.Snapshot()) {
			if idx.AppID == appID {
				check(a.Data.Rule)
			}
		}
		if i == 1 {
			a, err := d.FindAVPByName(appID, "External-Identifier")
			if err != nil || a.Must != "M,V" {
				t.Fatalf("Sh requires its local External-Identifier with M,V: %v, %v", a, err)
			}
		}
	}
}

func TestCxShVendorLookup(t *testing.T) {
	selection := []dict.Dictionary{dict.Base(), nasreq.Dictionary(), cx.Dictionary(), sh.Dictionary()}
	normal := newTestParser(t, selection...).Snapshot()
	// Reverse both file order and AVP declaration order before publication.
	var files []*dict.File
	for _, name := range []string{"base.xml", "network_access_server.xml", "tgpp_cx.xml", "tgpp_sh.xml"} {
		data, err := os.ReadFile(sourcePath(t, name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := dict.ParseXMLForTesting(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, app := range f.App {
			slices.Reverse(app.AVP)
		}
		files = append(files, f)
	}
	slices.Reverse(files)
	reversed, err := dict.SnapshotFromFilesForTesting(files)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 6733 §4.1 identifies AVPs by code and vendor. Declaration order
	// cannot change vendor-explicit lookup results.
	// A definition owned by Sh must win over an inherited Cx definition.
	codes := []uint32{621, 622, 623, 624, 625, 626, 648, 649, 650, 651, 652}
	for _, d := range []*dict.Snapshot{normal, reversed} {
		for _, app := range []uint32{16777216, 16777217} {
			for _, code := range codes {
				t.Run(fmt.Sprintf("%d/%d", app, code), func(t *testing.T) {
					gpp, err := d.FindAVP(app, code, 10415)
					if err != nil {
						t.Fatal(err)
					}
					ietf, err := d.FindAVP(app, code, 0)
					if err != nil || ietf == gpp || ietf.VendorID != 0 {
						t.Fatalf("IETF lookup lost: %v, %v", ietf, err)
					}
					for _, want := range []*dict.AVP{gpp, ietf} {
						if got, err := d.FindAVPByName(app, want.Name); err != nil || got != want {
							t.Fatalf("name lookup = %v, %v; want %v", got, err, want)
						}
					}
				})
			}
		}
	}
}

func TestShVendorZero623UsesOwnGroupedDefinition(t *testing.T) {
	d := newTestParser(t, dict.Base(), nasreq.Dictionary(), cx.Dictionary(), sh.Dictionary())
	app, err := d.App(16777217)
	if err != nil {
		t.Fatal(err)
	}
	var own *dict.AVP
	for _, candidate := range app.AVP {
		if candidate.Code == 623 && candidate.VendorID == 0 {
			own = candidate
			break
		}
	}
	if own == nil {
		t.Fatal("Sh dictionary has no own vendor-0 OC-OLR")
	}
	avp, err := d.FindAVP(16777217, uint32(623), 0)
	if err != nil || avp != own || avp.Name != "OC-OLR" || avp.Data.TypeName != "Grouped" {
		t.Fatalf("Sh vendor-0 623 = %v, %v; want its own vendor-0 OC-OLR %v", avp, err, own)
	}
	if rule, err := d.Rule(16777217, 623, 0, "OC-Sequence-Number"); err != nil || rule == nil || rule.AVP != "OC-Sequence-Number" {
		t.Fatalf("Sh OC-OLR rule = %v, %v", rule, err)
	}
	if enum, err := d.Enum(16777217, 623, 0, 0); err == nil || enum != nil {
		t.Fatalf("Sh vendor-0 623 must not resolve the Cx REGISTRATION enum: %v, %v", enum, err)
	}
	if gpp, err := d.FindAVP(16777217, 623, 10415); err != nil || gpp == nil || gpp.Name != "User-Authorization-Type" {
		t.Fatalf("Sh vendor-scoped 623 = %v, %v; want inherited Cx AVP", gpp, err)
	}
}

func TestRxInheritsFramedIPv6Prefix(t *testing.T) {
	d := newTestParser(t, rx.Dictionary(), creditcontrol.Dictionary(), rorf.Dictionary(), nasreq.Dictionary(), dict.Base())
	want, err := d.FindAVPByName(1, "Framed-IPv6-Prefix")
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.FindAVPByName(16777236, "Framed-IPv6-Prefix")
	if err != nil || got != want {
		t.Fatalf("Rx must inherit RFC 7155 §4.4.10.5.6: %v, %v", got, err)
	}
	cmd, err := d.FindCommand(16777236, 265)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range cmd.Request.Rule {
		if r.AVP == "Framed-IPv6-Prefix" {
			return
		}
	}
	t.Fatal("Rx AAR missing canonical Framed-IPv6-Prefix rule")
}
