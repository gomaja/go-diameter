package dict

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInheritanceParentsMustBeDeclared(t *testing.T) {
	for _, tc := range []struct {
		name, declarations, child, parent string
		register                          bool
		notFound                          bool
	}{
		{"missing", `<application id="40" inherits="999"/>`, "40", "999", false, true},
		{"registered only", `<application id="40" inherits="999"/>`, "40", "999", true, true},
		{"transitive missing", `<application id="40" inherits="41"/><application id="41" inherits="999"/>`, "41", "999", false, true},
		{"relay absent", `<application id="40" inherits="4294967295"/>`, "40", "4294967295", false, false},
		{"relay declared", `<application id="40" inherits="4294967295"/><application id="4294967295"/>`, "40", "4294967295", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Base)
			if tc.register {
				mustRegister(t, p, 999, &AVP{Name: "Registered", Code: 70001, Data: Data{TypeName: "Unsigned32"}})
			}
			before := p.Snapshot()
			dump := dumpSnapshot(before)
			err := p.Load(strings.NewReader(`<diameter><application id="77"/></diameter>`), strings.NewReader("<diameter>"+tc.declarations+"</diameter>"))
			if err == nil {
				t.Fatal("Load accepted invalid parent; want child/parent error")
			}
			for _, part := range []string{"application " + tc.child, "parent " + tc.parent} {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error %q lacks %q", err, part)
				}
			}
			if tc.notFound && !errors.Is(err, ErrNotFound) {
				t.Errorf("error %v does not wrap ErrNotFound", err)
			}
			if !tc.notFound && !strings.Contains(err.Error(), "Relay") {
				t.Errorf("error %v does not explain Relay", err)
			}
			if p.Snapshot() != before {
				t.Error("rejected parent load published a snapshot")
			}
			diffDumps(t, "rejected parent", dumpSnapshot(p.Snapshot()), dump)
		})
	}
	// Parent discovery covers the complete transaction, not just earlier streams.
	child := `<diameter><application id="40" inherits="999"/></diameter>`
	parent := `<diameter><application id="999"><avp name="From-Parent" code="70001"><data type="Unsigned32"/></avp></application></diameter>`
	for _, mode := range []string{"later stream", "earlier load", "later file"} {
		t.Run(mode, func(t *testing.T) {
			p := new(Parser)
			var err error
			switch mode {
			case "later stream":
				err = p.Load(strings.NewReader(child), strings.NewReader(parent))
			case "earlier load":
				if err = p.Load(strings.NewReader(parent)); err != nil {
					t.Fatal(err)
				}
				err = p.Load(strings.NewReader(child))
			case "later file":
				dir := t.TempDir()
				c, f := filepath.Join(dir, "child.xml"), filepath.Join(dir, "parent.xml")
				if err = os.WriteFile(c, []byte(child), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f, []byte(parent), 0600); err != nil {
					t.Fatal(err)
				}
				err = p.LoadFile(c, f)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.FindAVPByName(40, "From-Parent"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInheritanceBaseAlwaysLast(t *testing.T) {
	p := new(Parser)
	if err := p.Load(strings.NewReader(`<diameter>
 <application id="40" inherits="0 41"/>
 <application id="0"><avp name="Base-Name" code="70001" vendor-id="10415"><data type="Unsigned32"/></avp></application>
 <application id="41"><avp name="Parent-Name" code="70001" vendor-id="10415"><data type="Unsigned32"/></avp></application>
 </diameter>`)); err != nil {
		t.Fatal(err)
	}
	a, err := p.FindAVP(40, 70001, 10415)
	if err != nil || a.Name != "Parent-Name" {
		t.Fatalf("base-last code lookup = %v, %v; want Parent-Name", a, err)
	}
	if b, err := p.FindAVPByName(40, "Parent-Name"); err != nil || b != a {
		t.Errorf("base-last name lookup = %v, %v", b, err)
	}
	if b, err := p.FindAVPByName(40, "Base-Name"); b != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("base name revived = %v, %v", b, err)
	}
}

func TestInheritanceCrossBranchNameConflicts(t *testing.T) {
	for _, second := range []struct{ code, vendor uint32 }{{70002, 10415}, {70001, 99999}} {
		for _, mode := range []string{"siblings", "transitive", "same precedence"} {
			t.Run(fmt.Sprintf("load/%v/%s", second, mode), func(t *testing.T) {
				p := New(Base)
				before := p.Snapshot()
				dump := dumpSnapshot(before)
				graph := `<application id="40" inherits="41 42"/>`
				if mode == "transitive" {
					graph = `<application id="40" inherits="43 42"/><application id="43" inherits="41"/>`
				}
				if mode == "same precedence" {
					graph += `<application id="41" inherits="42"/>`
				}
				graph += nameDefinition(41, 70001, 10415, "Foo", "Unsigned32") + nameDefinition(42, second.code, second.vendor, "Foo", "Unsigned32")
				err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>"))
				assertInheritanceNameConflict(t, err, second.code, second.vendor)
				if p.Snapshot() != before {
					t.Error("name conflict published a snapshot")
				}
				diffDumps(t, "name conflict", dumpSnapshot(p.Snapshot()), dump)
			})
		}
		t.Run(fmt.Sprintf("register/%v", second), func(t *testing.T) {
			p := New(Base)
			graph := `<application id="40" inherits="41 42"/><application id="42"/>` + nameDefinition(41, 70001, 10415, "Foo", "Unsigned32")
			if err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>")); err != nil {
				t.Fatal(err)
			}
			before := p.Snapshot()
			dump := dumpSnapshot(before)
			err := p.RegisterAVP(42, &AVP{Name: "Unpublished", Code: 70003, Data: Data{TypeName: "Unsigned32"}}, &AVP{Name: "Foo", Code: second.code, VendorID: second.vendor, Data: Data{TypeName: "Unsigned32"}})
			assertInheritanceNameConflict(t, err, second.code, second.vendor)
			if p.Snapshot() != before {
				t.Error("name conflict registration published a snapshot")
			}
			diffDumps(t, "registration conflict", dumpSnapshot(p.Snapshot()), dump)
		})
	}
	t.Run("chain shadowing retained", func(t *testing.T) {
		p := new(Parser)
		graph := `<application id="40" inherits="41"/>` + nameDefinition(41, 70001, 10415, "Foo", "Unsigned32") + nameDefinition(40, 70002, 10415, "Foo", "Unsigned32")
		if err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>")); err != nil {
			t.Fatal(err)
		}
		if a, err := p.FindAVPByName(40, "Foo"); err != nil || a.Code != 70002 {
			t.Errorf("chain shadowing = %v, %v; want nearer code 70002", a, err)
		}
		if _, err := p.FindAVP(40, 70001, 10415); err != nil {
			t.Errorf("ancestor wire identity lost: %v", err)
		}
	})
	t.Run("nearer identity renamed", func(t *testing.T) {
		p := new(Parser)
		graph := `<application id="40" inherits="41"/>` + nameDefinition(41, 70001, 10415, "Old-Name", "Unsigned32") + nameDefinition(40, 70001, 10415, "New-Name", "Unsigned32")
		if err := p.Load(strings.NewReader("<diameter>" + graph + "</diameter>")); err != nil {
			t.Fatal(err)
		}
		a, err := p.FindAVP(40, 70001, 10415)
		if err != nil || a.Name != "New-Name" {
			t.Fatalf("renamed identity = %v, %v", a, err)
		}
		if b, err := p.FindAVPByName(40, "New-Name"); err != nil || b != a {
			t.Errorf("renamed lookup = %v, %v", b, err)
		}
		if a, err := p.FindAVPByName(40, "Old-Name"); a != nil || !errors.Is(err, ErrNotFound) {
			t.Errorf("old inherited name revived = %v, %v", a, err)
		}
	})
}

func assertInheritanceNameConflict(t *testing.T, err error, code, vendor uint32) {
	t.Helper()
	if !errors.Is(err, ErrAVPConflict) {
		t.Fatalf("cross-branch name collision = %v; want ErrAVPConflict", err)
	}
	for _, part := range []string{"application 40", "Foo", "code 70001", "vendor 10415", fmt.Sprintf("code %d", code), fmt.Sprintf("vendor %d", vendor)} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q lacks %q", err, part)
		}
	}
}

func TestUnresolvedRuleExplainsInheritance(t *testing.T) {
	for _, body := range []string{
		`<avp name="Custom" code="70001"><data type="Grouped"><rule avp="Service-Information"/></data></avp>`,
		`<command code="900" name="Custom"><request><rule avp="Service-Information"/></request><answer/></command>`,
		`<command code="900" name="Custom"><request/><answer><rule avp="Service-Information"/></answer></command>`,
	} {
		p := New(RoRf)
		before := p.Snapshot()
		err := p.Load(strings.NewReader(`<diameter><application id="16777238">` + body + `</application></diameter>`))
		if !errors.Is(err, ErrAVPConflict) || !errors.Is(err, ErrNotFound) {
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
