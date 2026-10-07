package dict

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDeclaredInheritance(t *testing.T) {
	const document = `<diameter>
 <application id="0"><avp name="Base" code="90"><data type="Unsigned32"/></avp></application>
 <application id="40" inherits="41&#9;42&#10;41"><avp name="Own" code="1"><data type="Unsigned32"/></avp></application>
 <application id="40" inherits="43 42 0 4294967294"/>
 <application id="4294967294"><avp name="HighestParent" code="9"><data type="Unsigned32"/></avp></application>
 <application id="41" inherits="44"><avp name="AncestorOwn" code="1"><data type="Unsigned32"/></avp><avp name="FirstParent" code="8"><data type="Unsigned32"/></avp><avp name="Left" code="2"><data type="Unsigned32"/></avp></application>
 <application id="42" inherits="44"><avp name="LaterParent" code="8"><data type="Unsigned32"/></avp><avp name="Right" code="3"><data type="Unsigned32"/></avp><avp name="Near" code="4"><data type="Unsigned32"/></avp></application>
 <application id="43"><avp name="Union" code="5"><data type="Unsigned32"/></avp></application>
 <application id="44"><avp name="Transitive" code="7"><data type="Unsigned32"/></avp><avp name="Far" code="4"><data type="Unsigned32"/></avp></application>
 </diameter>`
	p := new(Parser)
	if err := p.Load(strings.NewReader(document)); err != nil {
		t.Fatal(err)
	}
	want := map[uint32]string{1: "Own", 2: "Left", 3: "Right", 4: "Near", 5: "Union", 7: "Transitive", 8: "FirstParent", 9: "HighestParent", 90: "Base"}
	for code, name := range want {
		a, err := p.FindAVP(40, code, 0)
		if err != nil || a.Name != name {
			t.Errorf("%d: %v, %v; want %s", code, a, err, name)
		}
		b, err := p.FindAVPByName(40, name)
		if err != nil || a != b {
			t.Errorf("name %s: %v, %v", name, b, err)
		}
	}
	if _, err := p.FindAVPByName(40, "Far"); !errors.Is(err, ErrNotFound) {
		t.Errorf("shadowed name revived: %v", err)
	}
	before := p.Snapshot()
	if err := p.Load(strings.NewReader(`<diameter><application id="40" inherits="45"/><application id="45"><avp name="Late" code="6"><data type="Unsigned32"/></avp></application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FindAVP(40, 6, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := before.FindAVP(40, 6, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("old snapshot changed: %v", err)
	}
	// XML marshaling must retain the declared graph, including duplicate declarations.
	b, err := xml.Marshal(p.Snapshot().files[0])
	if err != nil {
		t.Fatal(err)
	}
	round := new(Parser)
	if err := round.Load(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	for code, name := range want {
		if a, err := round.FindAVP(40, code, 0); err != nil || a.Name != name {
			t.Errorf("round trip code %d = %v, %v; want %s", code, a, err, name)
		}
	}
}

func TestInheritanceSyntaxAndCycles(t *testing.T) {
	for _, bad := range []string{"", " ", "-1", "+1", "0x4", "4,1", "4294967296", "4 nope"} {
		t.Run("syntax_"+bad, func(t *testing.T) {
			p := new(Parser)
			err := p.Load(strings.NewReader(fmt.Sprintf(`<diameter><application id="40" inherits="%s"/></diameter>`, bad)))
			if err == nil || !strings.Contains(err.Error(), "invalid inherits") {
				t.Fatalf("error %v, want invalid inherits", err)
			}
		})
	}
	for _, graph := range []string{`<application id="40" inherits="40"/>`, `<application id="40" inherits="41"/><application id="41" inherits="40"/>`, `<application id="40" inherits="41 42"/><application id="41"/><application id="42" inherits="40"/>`, `<application id="0" inherits="40"/>`} {
		t.Run(graph, func(t *testing.T) {
			p := New(Base)
			before := p.Snapshot()
			err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>"))
			if !errors.Is(err, ErrParentCycle) {
				t.Fatalf("error %v, want ErrParentCycle", err)
			}
			if p.Snapshot() != before {
				t.Fatal("failed cycle load published snapshot")
			}
		})
	}
}

// RFC 6733 §§2.4, 9.7: accounting acquires the TS 32.299 §6.2 tree
// only through the loaded Ro/Rf contribution to application 3.
func TestAccountingInheritanceIsBundleScoped(t *testing.T) {
	for _, b := range []Bundled{Base, NASREQ, Cx, Sh} {
		p := New(b)
		count := 0
		for _, app := range Default.Apps() {
			for _, a := range app.AVP {
				if _, err := p.FindAVP(3, a.Code, a.VendorID); err == nil {
					count++
				}
			}
		}
		// Enumerate identities independently of duplicate bundle declarations.
		keys := map[[2]uint32]bool{}
		for _, app := range Default.Apps() {
			for _, a := range app.AVP {
				if _, err := p.FindAVP(3, a.Code, a.VendorID); err == nil {
					keys[[2]uint32{a.Code, a.VendorID}] = true
				}
			}
		}
		if len(keys) != 63 {
			t.Errorf("%s accounting has %d distinct AVPs (%d definitions), want 63", b, len(keys), count)
		}
		for key := range keys {
			got, _ := p.FindAVP(3, key[0], key[1])
			base, err := p.FindAVP(0, key[0], key[1])
			if err != nil || got != base {
				t.Errorf("%s app 3 differs from base at %v", b, key)
			}
		}
	}
	for _, b := range []Bundled{RoRf, CreditControl, Gx, Rx, S6a, SWx, S6c, SGd, Sy} {
		p := New(b)
		if _, err := p.FindAVPByName(3, "Service-Information"); err != nil {
			t.Errorf("%s lacks Rf charging: %v", b, err)
		}
	}
}
