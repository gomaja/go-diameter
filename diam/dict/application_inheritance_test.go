package dict_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/gx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
	"github.com/gomaja/go-diameter/diam/dict/rx"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
	"github.com/gomaja/go-diameter/diam/dict/s6c"
	"github.com/gomaja/go-diameter/diam/dict/sgd"
	"github.com/gomaja/go-diameter/diam/dict/sh"
	"github.com/gomaja/go-diameter/diam/dict/swx"
	"github.com/gomaja/go-diameter/diam/dict/sy"
)

// RFC 6733 §§2.4, 9.7: accounting acquires the TS 32.299 §6.2 tree
// only through the loaded Ro/Rf contribution to application 3.
func TestAccountingInheritanceIsBundleScoped(t *testing.T) {
	reference := newAllTestParser(t)

	for _, b := range []dict.Dictionary{dict.Base(), nasreq.Dictionary(), cx.Dictionary(), sh.Dictionary()} {
		p := newTestParser(t, b)
		count := 0
		for _, app := range reference.Apps() {
			for _, a := range app.AVP {
				if _, err := p.FindAVP(3, a.Code, a.VendorID); err == nil {
					count++
				}
			}
		}
		// Enumerate identities independently of duplicate bundle declarations.
		keys := map[[2]uint32]bool{}
		for _, app := range reference.Apps() {
			for _, a := range app.AVP {
				if _, err := p.FindAVP(3, a.Code, a.VendorID); err == nil {
					keys[[2]uint32{a.Code, a.VendorID}] = true
				}
			}
		}
		if len(keys) != 63 {
			t.Errorf("%v accounting has %d distinct AVPs (%d definitions), want 63", b, len(keys), count)
		}
		for key := range keys {
			got, _ := p.FindAVP(3, key[0], key[1])
			base, err := p.FindAVP(0, key[0], key[1])
			if err != nil || got != base {
				t.Errorf("%v app 3 differs from base at %v", b, key)
			}
		}
	}
	for _, b := range []dict.Dictionary{rorf.Dictionary(), creditcontrol.Dictionary(), gx.Dictionary(), rx.Dictionary(), s6a.Dictionary(), swx.Dictionary(), s6c.Dictionary(), sgd.Dictionary(), sy.Dictionary()} {
		p := newTestParser(t, b)
		if _, err := p.FindAVPByName(3, "Service-Information"); err != nil {
			t.Errorf("%v lacks Rf charging: %v", b, err)
		}
	}
}

func TestShCxParentViews(t *testing.T) {
	t.Run("Sh Cx", func(t *testing.T) {
		p := newTestParser(t, sh.Dictionary())
		if a, err := p.FindAVPByName(16777217, "User-Data"); err != nil || a.Code != 702 {
			t.Fatalf("Sh User-Data = %v, %v", a, err)
		}
		if a, err := p.FindAVP(16777217, 606, 10415); err != nil || a.Name != "User-Data" {
			t.Fatalf("Cx User-Data in Sh = %v, %v", a, err)
		}
	})
}

func TestUnresolvedRuleExplainsInheritance(t *testing.T) {
	for _, body := range []string{
		`<avp name="Custom" code="70001"><data type="Grouped"><rule avp="Service-Information"/></data></avp>`,
		`<command code="900" name="Custom"><request><rule avp="Service-Information"/></request><answer/></command>`,
		`<command code="900" name="Custom"><request/><answer><rule avp="Service-Information"/></answer></command>`,
	} {
		p := newTestParser(t, rorf.Dictionary())
		before := p.Snapshot()
		err := p.Load(strings.NewReader(`<diameter><application id="16777238">` + body + `</application></diameter>`))
		if !errors.Is(err, dict.ErrAVPConflict) || !errors.Is(err, dict.ErrNotFound) {
			t.Fatalf("unresolved rule = %v; want ErrAVPConflict and ErrNotFound", err)
		}
		for _, part := range []string{"Service-Information", "application 16777238", "inherited definitions require", "defining application", "inherits attribute"} {
			if !strings.Contains(err.Error(), part) {
				t.Errorf("unresolved rule error lacks %q: %v", part, err)
			}
		}
		if p.Snapshot() != before {
			t.Error("unresolved rule published a snapshot")
		}
	}
}
