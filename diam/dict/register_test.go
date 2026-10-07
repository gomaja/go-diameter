package dict

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testVendor = 99999 // An enterprise number no bundled dictionary uses.
	gxAppID    = 16777238
)

func vendorAVP(name string, code uint32, typ string) *AVP {
	return &AVP{Name: name, Code: code, VendorID: testVendor, Must: "V", MustNot: "M", Data: Data{TypeName: typ}}
}

// mustRegister registers avps in app and fails the test on error.
func mustRegister(t *testing.T, p *Parser, app uint32, avps ...*AVP) {
	t.Helper()
	if err := p.RegisterAVP(app, avps...); err != nil {
		t.Fatal(err)
	}
}

// requireUnchanged fails unless p still publishes before.
func requireUnchanged(t *testing.T, p *Parser, before *Snapshot) {
	t.Helper()
	if p.Snapshot() != before {
		t.Fatal("the Parser published a new Snapshot")
	}
}

// TestRegisterAVPIsVendorScoped registers code 9 for a third vendor in
// application 4, where code 9 is Framed-IP-Netmask for vendor 0 (RFC 7155)
// and TGPP-GGSN-MCC-MNC for 3GPP (TS 29.061). RFC 6733 §4.1: the code and
// the vendor together identify an AVP.
func TestRegisterAVPIsVendorScoped(t *testing.T) {
	p := New(AllBundled()...)
	ietf, err := p.FindAVP(4, uint32(9), 0)
	if err != nil {
		t.Fatal(err)
	}
	mustRegister(t, p, 4, vendorAVP("Test-Code-Nine", 9, "Unsigned32"))
	for _, tc := range []struct {
		vendor uint32
		name   string
	}{
		{0, "Framed-IP-Netmask"},
		{10415, "TGPP-GGSN-MCC-MNC"},
		{testVendor, "Test-Code-Nine"},
	} {
		for _, app := range []uint32{4, gxAppID} {
			if avp, err := p.FindAVP(app, 9, tc.vendor); err != nil || avp.Name != tc.name {
				t.Errorf("app %d code 9 vendor %d = %v, %v; want %s", app, tc.vendor, avp, err, tc.name)
			}
		}
	}
	if avp, err := p.FindAVP(4, uint32(9), 0); err != nil || avp != ietf {
		t.Errorf("vendor-0 code 9 = %v, %v; want %s unchanged", avp, err, ietf.Name)
	}
	assertNoWildcardRegistrations(t, p.Snapshot())

	// A vendor-specific registration cannot answer a vendor-0 lookup.
	fresh := New()
	mustRegister(t, fresh, 4, &AVP{Name: "TGPP-GGSN-MCC-MNC", Code: 9, VendorID: 10415, Must: "V", Data: Data{TypeName: "UTF8String"}})
	if avp, err := fresh.FindAVP(4, 9, 0); err == nil {
		t.Errorf("code 9 vendor 0 = %v", avp)
	}
	assertNoWildcardRegistrations(t, fresh.Snapshot())
}

// assertNoWildcardRegistrations checks every code index retains its vendor.
func assertNoWildcardRegistrations(t *testing.T, s *Snapshot) {
	t.Helper()
	for idx, avp := range s.avpcode {
		if idx.vendorID != avp.VendorID {
			t.Errorf("%s indexed under vendor %d, want %d", avp.Name, idx.vendorID, avp.VendorID)
		}
	}
}

func TestRegisterAVPRejectsInvalidDefinitions(t *testing.T) {
	grouped := func(rules ...*Rule) *AVP {
		a := vendorAVP("Test-Group", 70000, "Grouped")
		a.Data.Rule = rules
		return a
	}
	with := func(f func(*AVP)) *AVP {
		a := vendorAVP("Test-AVP", 70001, "UTF8String")
		f(a)
		return a
	}
	for _, tc := range []struct {
		name string
		avp  *AVP
		want string
	}{
		{"nil", nil, "nil definition"},
		{"empty name", with(func(a *AVP) { a.Name = "" }), "name"},
		{"name starts with a digit", with(func(a *AVP) { a.Name = "3GPP-Thing" }), "name"},
		{"name with underscore", with(func(a *AVP) { a.Name = "Test_AVP" }), "name"},
		{"name with space", with(func(a *AVP) { a.Name = "Test AVP" }), "name"},
		{"name AVP", with(func(a *AVP) { a.Name = "AVP" }), "any AVP"},
		{"code 0", with(func(a *AVP) { a.Code = 0 }), "code 0"},
		{"unknown type", with(func(a *AVP) { a.Data.TypeName = "Unknown" }), "data type"},
		{"no type", with(func(a *AVP) { a.Data.TypeName = "" }), "data type"},
		{"items on non-enumerated", with(func(a *AVP) { a.Data.Enum = []*Enum{{Code: 1, Name: "ONE"}} }), "Enumerated"},
		{"nil item", with(func(a *AVP) { a.Data.TypeName = "Enumerated"; a.Data.Enum = []*Enum{nil} }), "nil enumerated"},
		{"rules on non-grouped", with(func(a *AVP) { a.Data.Rule = []*Rule{{AVP: "Session-Id"}} }), "Grouped"},
		{"unknown flag", with(func(a *AVP) { a.Must = "V,X" }), "unknown flag"},
		{"bad may", with(func(a *AVP) { a.May = "Q" }), "may flags"},
		{"required and forbidden", with(func(a *AVP) { a.Must = "M,V"; a.MustNot = "M" }), "both"},
		{"V without vendor", with(func(a *AVP) { a.VendorID = 0; a.Must = "M,V"; a.MustNot = "" }), "no vendor"},
		{"V forbidden with vendor", with(func(a *AVP) { a.Must = ""; a.MustNot = "V" }), "has a vendor"},
		{"nil rule", grouped(nil), "nil member"},
		{"bad member name", grouped(&Rule{AVP: "Not a name"}), "not an AVP name"},
		{"member twice", grouped(&Rule{AVP: "Session-Id"}, &Rule{AVP: "Session-Id"}), "more than one"},
		{"negative minimum", grouped(&Rule{AVP: "Session-Id", Min: -1}), "negative"},
		{"maximum below minimum", grouped(&Rule{AVP: "Session-Id", Min: 2, Max: 1}), "below its minimum"},
		{"required member never allowed", grouped(&Rule{AVP: "Session-Id", Required: true, MaxSet: true}), "below its minimum"},
		{"unresolved member", grouped(&Rule{AVP: "No-Such-AVP"}), "does not resolve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Base)
			before := p.Snapshot()
			err := p.RegisterAVP(4, tc.avp)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RegisterAVP error = %v, want one mentioning %q", err, tc.want)
			}
			requireUnchanged(t, p, before)
		})
	}
}

func TestRegisterAVPConflicts(t *testing.T) {
	p := New(AllBundled()...)
	mustRegister(t, p, 4, vendorAVP("Test-Alpha", 70000, "UTF8String"))
	for _, tc := range []struct {
		name string
		app  uint32
		avps []*AVP
	}{
		{"same code and vendor, other name", 4, []*AVP{vendorAVP("Test-Beta", 70000, "UTF8String")}},
		{"same code and vendor, other type", 4, []*AVP{vendorAVP("Test-Alpha", 70000, "OctetString")}},
		{"same name and vendor, other code", 4, []*AVP{vendorAVP("Test-Alpha", 70001, "UTF8String")}},
		{"same name, other vendor", 4, []*AVP{{Name: "Test-Alpha", Code: 70000, VendorID: 94, Must: "V", Data: Data{TypeName: "UTF8String"}}}},
		{"inherited by a child application", gxAppID, []*AVP{vendorAVP("Test-Alpha", 70000, "Integer32")}},
		{"name of a loaded AVP", 4, []*AVP{vendorAVP("Session-Id", 70002, "UTF8String")}},
		{"redefines a loaded AVP", 4, []*AVP{{Name: "Session-Id", Code: 263, Must: "M", Data: Data{TypeName: "OctetString"}}}},
		{"conflict within the call", 4, []*AVP{vendorAVP("Test-Gamma", 70003, "UTF8String"), vendorAVP("Test-Delta", 70003, "UTF8String")}},
		{"valid one first, conflict second", 4, []*AVP{vendorAVP("Test-Epsilon", 70004, "UTF8String"), vendorAVP("Test-Beta", 70000, "UTF8String")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := p.Snapshot()
			err := p.RegisterAVP(tc.app, tc.avps...)
			if !errors.Is(err, ErrAVPConflict) {
				t.Fatalf("RegisterAVP error = %v, want ErrAVPConflict", err)
			}
			requireUnchanged(t, p, before)
		})
	}
	if avp, err := p.FindAVP(4, 70004, testVendor); err == nil {
		t.Errorf("a refused call registered %s", avp.Name)
	}
}

func TestRegisterAVPIdenticalIsNoOp(t *testing.T) {
	p := New(AllBundled()...)
	alpha := vendorAVP("Test-Alpha", 70000, "UTF8String")
	mustRegister(t, p, 4, alpha)
	before := p.Snapshot()
	again := vendorAVP("Test-Alpha", 70000, "UTF8String")
	again.Must, again.MustNot = " V ", "M" // the same rules, written differently
	mustRegister(t, p, 4, again)
	mustRegister(t, p, gxAppID, alpha)     // already inherited from application 4
	mustRegister(t, p, 4, alpha, alpha)    // a duplicate within one call
	sessionID, err := p.FindAVP(0, 263, 0) // a loaded AVP, copied field by field
	if err != nil {
		t.Fatal(err)
	}
	copied := *sessionID
	mustRegister(t, p, 4, &copied)
	requireUnchanged(t, p, before)
	if n := len(p.Snapshot().regs); n != 1 {
		t.Fatalf("%d registrations, want 1", n)
	}
}

// TestRegisterAVPIdenticalByCodeStillChecksName: a definition that the
// application already has by code and vendor is not a no-op when its name
// denotes another AVP there. Application 4 inherits Test-Member 70001 from
// the base application but defines its own Test-Member 70002, so a Grouped
// AVP registered with the base member would get a rule that resolves to
// 70002 and rejects the 70001 it was given (RFC 6733 §4.4: a rule names
// one AVP).
func TestRegisterAVPIdenticalByCodeStillChecksName(t *testing.T) {
	p := New()
	if err := p.Load(strings.NewReader(`<diameter>
		<application id="0"><avp name="Test-Member" code="70001" must="V" vendor-id="99999"><data type="Unsigned32"/></avp></application>
		<application id="4"><avp name="Test-Member" code="70002" must="V" vendor-id="99999"><data type="UTF8String"/></avp></application>
	</diameter>`)); err != nil {
		t.Fatal(err)
	}
	member, err := p.FindAVP(0, 70001, testVendor)
	if err != nil {
		t.Fatal(err)
	}
	if have, err := p.FindAVP(4, 70001, testVendor); err != nil || have != member {
		t.Fatalf("application 4 does not inherit the base member: %v, %v", have, err)
	}
	group := vendorAVP("Test-Group", 70000, "Grouped")
	group.Data.Rule = []*Rule{{AVP: "Test-Member", Required: true, Max: 1}}
	for name, avps := range map[string][]*AVP{
		"member alone":     {member},
		"group and member": {group, member},
		"member and group": {member, group},
	} {
		t.Run(name, func(t *testing.T) {
			before := p.Snapshot()
			if err := p.RegisterAVP(4, avps...); !errors.Is(err, ErrAVPConflict) {
				t.Fatalf("RegisterAVP error = %v, want ErrAVPConflict", err)
			}
			requireUnchanged(t, p, before)
		})
	}
	// In the base application, where the name denotes it, it is a no-op.
	before := p.Snapshot()
	mustRegister(t, p, 0, member)
	requireUnchanged(t, p, before)
}

// TestFindAVPInheritsInUndeclaredApplications: an application that no
// dictionary declares inherits from its ancestors (parentAppIds) for the
// decoder too, for loaded and registered AVPs alike.
func TestFindAVPInheritsInUndeclaredApplications(t *testing.T) {
	registered := New(Base)
	mustRegister(t, registered, 4, vendorAVP("Test-Counter", 70000, "Unsigned32"))
	mustRegister(t, registered, 0, vendorAVP("Test-Base-Vendor", 70001, "Unsigned32"))
	loaded := New(Base)
	if err := loaded.Load(strings.NewReader(`<diameter>
		<application id="4" type="auth" name="Test">
			<avp name="Test-Counter" code="70000" must="V" must-not="M" vendor-id="99999"><data type="Unsigned32"/></avp>
		</application>
		<application id="0">
			<avp name="Test-Base-Vendor" code="70001" must="V" must-not="M" vendor-id="99999"><data type="Unsigned32"/></avp>
		</application>
	</diameter>`)); err != nil {
		t.Fatal(err)
	}
	keys := []struct{ code, vendor uint32 }{{70000, testVendor}, {70001, testVendor}, {263, 0}, {70002, testVendor}}
	apps := []uint32{0, 1, 3, 4, 16777236, 16777238, 16777251, 16777252, 16777265, 16777302, 16777312, 16777313, 16777999}
	for name, p := range map[string]*Parser{"registered": registered, "loaded": loaded} {
		for _, app := range apps {
			for _, key := range keys {
				want := ""
				switch key.code {
				case 70000:
					switch app {
					case 4, 16777236, 16777238, 16777251, 16777265, 16777302, 16777312, 16777313:
						want = "Test-Counter"
					}
				case 70001:
					want = "Test-Base-Vendor"
				case 263:
					want = "Session-Id"
				}
				got, err := p.FindAVP(app, key.code, key.vendor)
				if want == "" {
					if err == nil {
						t.Errorf("%s: app %d key %v = %v; want miss", name, app, key, got)
					}
				} else if err != nil || got.Name != want || got.VendorID != key.vendor {
					t.Errorf("%s: app %d key %v = %v, %v; want %s", name, app, key, got, err, want)
				}

			}
		}
		// Gx, Rx, Sy and S6c descend from application 4; SWx through S6a
		// and S6c. Application 1, its parent, and S13 do not.
		for app, want := range map[uint32]bool{16777238: true, 16777265: true, 16777313: true, 1: false, 16777252: false} {
			if _, err := p.FindAVP(app, 70000, testVendor); (err == nil) != want {
				t.Errorf("%s: app %d Test-Counter found = %t, want %t", name, app, err == nil, want)
			}
		}
	}
}

// TestRegisterAVPInheritsLikeLoad checks that a registered AVP is visible
// in exactly the applications where the same AVP loaded from XML is.
func TestRegisterAVPInheritsLikeLoad(t *testing.T) {
	registered := New(AllBundled()...)
	shadow := vendorAVP("Test-Shadowed", 1001, "UTF8String")
	shadow.VendorID = 10415 // Gx defines Charging-Rule-Install with this code
	mustRegister(t, registered, 4, vendorAVP("Test-Inherited", 70000, "UTF8String"), shadow)

	loaded := New(AllBundled()...)
	if err := loaded.Load(strings.NewReader(`<diameter><application id="4">
		<avp name="Test-Inherited" code="70000" must="V" must-not="M" vendor-id="99999"><data type="UTF8String"/></avp>
		<avp name="Test-Shadowed" code="1001" must="V" must-not="M" vendor-id="10415"><data type="UTF8String"/></avp>
	</application></diameter>`)); err != nil {
		t.Fatal(err)
	}

	for _, app := range []uint32{0, 1, 3, 4, 16777236, 16777238, 16777251, 16777252, 16777265, 16777302, 16777312, 16777313, 16777999} {
		for _, key := range []struct{ code, vendor uint32 }{{70000, testVendor}, {1001, 10415}} {
			r, rerr := registered.FindAVP(app, key.code, key.vendor)
			l, lerr := loaded.FindAVP(app, key.code, key.vendor)
			if (rerr == nil) != (lerr == nil) || (rerr == nil && r.Name != l.Name) {
				t.Errorf("app %d code %d vendor %d: registered %v (%v), loaded %v (%v)",
					app, key.code, key.vendor, r, rerr, l, lerr)
			}
		}
		r, rerr := registered.FindAVPByName(app, "Test-Inherited")
		l, lerr := loaded.FindAVPByName(app, "Test-Inherited")
		if (rerr == nil) != (lerr == nil) || (rerr == nil && r.Code != l.Code) {
			t.Errorf("app %d by name and vendor: registered %v (%v), loaded %v (%v)", app, r, rerr, l, lerr)
		}
	}
	// Spot checks: children see it, the parent and unrelated applications
	// do not, and Gx keeps its own definition of code 1001.
	for app, want := range map[uint32]string{
		16777238: "Test-Inherited", 16777265: "Test-Inherited", 16777313: "Test-Inherited",
		1: "", 0: "", 16777252: "",
	} {
		avp, err := registered.FindAVP(app, 70000, testVendor)
		if want == "" && err == nil || want != "" && (err != nil || avp.Name != want) {
			t.Errorf("app %d: %v, %v; want %q", app, avp, err, want)
		}
	}
	if avp, _ := registered.FindAVP(gxAppID, 1001, 10415); avp.Name != "Charging-Rule-Install" {
		t.Errorf("Gx code 1001 = %s, want its own Charging-Rule-Install", avp.Name)
	}
	if avp, _ := registered.FindAVP(16777236, 1001, 10415); avp.Name != "Test-Shadowed" {
		t.Errorf("Rx code 1001 = %s, want Test-Shadowed from application 4", avp.Name)
	}
}

func TestRegisterAVPDeclaresNoApplication(t *testing.T) {
	const private = 16777999
	p := New(Base)
	appsBefore := fmt.Sprint(p.Apps())
	mustRegister(t, p, private, vendorAVP("Test-Private", 70000, "UTF8String"))
	if apps := fmt.Sprint(p.Apps()); apps != appsBefore {
		t.Errorf("Apps() = %s, was %s", apps, appsBefore)
	}
	if _, err := p.App(private); !errors.Is(err, ErrApplicationUnsupported) {
		t.Errorf("App(%d) error = %v, want ErrApplicationUnsupported", private, err)
	}
	if avp, err := p.FindAVP(private, 70000, testVendor); err != nil || avp.App.ID != private {
		t.Errorf("registered AVP = %v, %v", avp, err)
	}
	if !strings.Contains(p.String(), "Test-Private") {
		t.Error("String() omits the registered AVP")
	}
}

func TestRegisterAVPSurvivesLoad(t *testing.T) {
	p := New(Base)
	mustRegister(t, p, 4, vendorAVP("Test-Kept", 70000, "UTF8String"))
	load := func(avp string) error {
		return p.Load(strings.NewReader(`<diameter><application id="4" type="auth" name="Test">` + avp + `</application></diameter>`))
	}
	if err := load(`<avp name="Test-Other" code="70001" must="V" must-not="M" vendor-id="99999"><data type="Unsigned32"/></avp>`); err != nil {
		t.Fatal(err)
	}
	// The same definition, loaded, changes nothing.
	if err := load(`<avp name="Test-Kept" code="70000" must="V" must-not="M" vendor-id="99999"><data type="UTF8String"/></avp>`); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{
		// Another meaning for the registered code and vendor.
		`<avp name="Test-Kept" code="70000" must="V" must-not="M" vendor-id="99999"><data type="OctetString"/></avp>`,
		// Another AVP with the registered name and vendor.
		`<avp name="Test-Kept" code="70002" must="V" must-not="M" vendor-id="99999"><data type="UTF8String"/></avp>`,
		// Another AVP with the registered name, for another vendor.
		`<avp name="Test-Kept" code="70000" must="V" must-not="M" vendor-id="94"><data type="UTF8String"/></avp>`,
	} {
		before := p.Snapshot()
		if err := load(refused); !errors.Is(err, ErrAVPConflict) {
			t.Errorf("Load(%s) error = %v, want ErrAVPConflict", refused, err)
		}
		requireUnchanged(t, p, before)
	}
	// An ancestor application may define the name: the registration, nearer,
	// keeps it in application 4 and its descendants.
	if err := p.Load(strings.NewReader(`<diameter><application id="1" type="auth" name="Parent">
		<avp name="Test-Kept" code="70000" must="V" must-not="M" vendor-id="94"><data type="OctetString"/></avp>
	</application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	for app, vendor := range map[uint32]uint32{4: testVendor, gxAppID: testVendor, 1: 94} {
		if avp, err := p.FindAVPByName(app, "Test-Kept"); err != nil || avp.VendorID != vendor {
			t.Errorf("app %d Test-Kept = %v, %v; want vendor %d", app, avp, err, vendor)
		}
	}
	for _, key := range []struct{ code, vendor uint32 }{{70000, testVendor}, {70001, testVendor}} {
		if _, err := p.FindAVP(4, key.code, key.vendor); err != nil {
			t.Error(err)
		}
	}
	if _, err := p.App(4); err != nil {
		t.Errorf("the loaded dictionary declares application 4: %v", err)
	}
}

func TestRegisterAVPNameScope(t *testing.T) {
	p := New(Base)
	// A nearer application may register a name an ancestor gets later...
	mustRegister(t, p, 4, vendorAVP("Test-Name", 70000, "UTF8String"))
	mustRegister(t, p, 1, &AVP{Name: "Test-Name", Code: 70000, VendorID: 94, Must: "V", Data: Data{TypeName: "UTF8String"}})
	for app, vendor := range map[uint32]uint32{4: testVendor, gxAppID: testVendor, 1: 94} {
		if avp, err := p.FindAVPByName(app, "Test-Name"); err != nil || avp.VendorID != vendor {
			t.Errorf("app %d Test-Name = %v, %v; want vendor %d", app, avp, err, vendor)
		}
	}
	// ...but not take over a name it already resolves.
	before := p.Snapshot()
	if err := p.RegisterAVP(16777236, &AVP{Name: "Test-Name", Code: 70001, VendorID: 95, Must: "V", Data: Data{TypeName: "UTF8String"}}); !errors.Is(err, ErrAVPConflict) {
		t.Fatalf("RegisterAVP error = %v, want ErrAVPConflict", err)
	}
	requireUnchanged(t, p, before)
}

func TestRegisterGroupedAVP(t *testing.T) {
	p := New(Base)
	group := vendorAVP("Test-Group", 70000, "Grouped")
	group.Data.Rule = []*Rule{
		{AVP: "Test-Member", Required: true, Max: 1},
		{AVP: "Test-Level", Max: 1, MaxSet: true},
		{AVP: "Session-Id"},
		{AVP: "AVP"},
	}
	level := vendorAVP("Test-Level", 70002, "Enumerated")
	level.Data.Enum = []*Enum{{Code: 0, Name: "LOW"}, {Code: 1, Name: "HIGH"}}
	mustRegister(t, p, 4, group, vendorAVP("Test-Member", 70001, "UTF8String"), level)

	have, err := p.FindAVP(4, 70000, testVendor)
	if err != nil {
		t.Fatal(err)
	}
	if len(have.Data.Rule) != 4 || have.Data.Rule[0].AVP != "Test-Member" {
		t.Fatalf("rules = %v", have.Data.Rule)
	}
	// The members resolve by name, also from Gx, which no dictionary
	// declares here and whose lookups walk up to application 4.
	for _, rule := range have.Data.Rule[:3] {
		if _, err := p.FindAVPByName(gxAppID, rule.AVP); err != nil {
			t.Errorf("member %s: %v", rule.AVP, err)
		}
	}
	if avp, err := p.FindAVPByName(4, "Test-Level"); err != nil || len(avp.Data.Enum) != 2 {
		t.Errorf("Test-Level = %v, %v", avp, err)
	}
	// The definitions are copies: changing the arguments changes nothing.
	group.Data.Rule[0].AVP = "Changed"
	group.Data.Rule = nil
	level.Data.Enum[0].Name = "CHANGED"
	if have.Data.Rule[0].AVP != "Test-Member" {
		t.Error("registered rule follows the caller's change")
	}
	if avp, _ := p.FindAVP(4, 70002, testVendor); avp.Data.Enum[0].Name != "LOW" {
		t.Error("registered item follows the caller's change")
	}
}

func TestRegisterAVPOnFreshParsers(t *testing.T) {
	fromNewParser, err := NewParser()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*Parser{"NewParser()": fromNewParser, "zero Parser": new(Parser), "New()": New()} {
		t.Run(name, func(t *testing.T) {
			if !p.Strict() || p.MaxGroupedDepth() != DefaultMaxGroupedDepth {
				t.Fatalf("policy: strict %t, depth %d", p.Strict(), p.MaxGroupedDepth())
			}
			group := vendorAVP("Test-Group", 70000, "Grouped")
			group.Data.Rule = []*Rule{{AVP: "Test-Member"}}
			mustRegister(t, p, 0, group, vendorAVP("Test-Member", 70001, "UTF8String"))
			if avp, err := p.FindAVP(0, 70000, testVendor); err != nil || avp.Name != "Test-Group" {
				t.Errorf("by code: %v, %v", avp, err)
			}
			for _, app := range []uint32{0, 4, 16777999} {
				if avp, err := p.FindAVPByName(app, "Test-Member"); err != nil || avp.Code != 70001 {
					t.Errorf("app %d by name: %v, %v", app, avp, err)
				}
			}
			if apps := p.Apps(); len(apps) != 0 {
				t.Errorf("Apps() = %v", apps)
			}
			assertNoWildcardRegistrations(t, p.Snapshot())
		})
	}
}
