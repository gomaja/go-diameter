package dict

import (
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// dumpSnapshot renders every index of s, one sorted line per entry, so two
// Snapshots can be compared by content.
func dumpSnapshot(s *Snapshot) []string {
	vendor := func(v uint32) string {
		if v == UndefinedVendorID {
			return "*"
		}
		return strconv.FormatUint(uint64(v), 10)
	}
	rules := func(rs []*Rule) string {
		var b []string
		for _, r := range rs {
			b = append(b, fmt.Sprintf("%s/%t/%d/%d/%t/%t", r.AVP, r.Required, r.Min, r.Max, r.MaxSet, r.Fixed))
		}
		return strings.Join(b, ",")
	}
	sig := func(a *AVP) string {
		var enum []string
		for _, e := range a.Data.Enum {
			enum = append(enum, fmt.Sprintf("%d=%s", e.Code, e.Name))
		}
		return fmt.Sprintf("%s|%d|%d|%s(%d)|%s|%s|%s|%s|[%s]|[%s]", a.Name, a.Code, a.VendorID, a.Data.TypeName,
			a.Data.Type, a.Must, a.May, a.MustNot, a.MayEncrypt, strings.Join(enum, ","), rules(a.Data.Rule))
	}
	var lines []string
	for i, app := range s.Apps() {
		lines = append(lines, fmt.Sprintf("APPS %02d %d %s %s", i, app.ID, app.Type, app.Name))
	}
	for k, app := range s.appcode {
		lines = append(lines, fmt.Sprintf("APPCODE %d -> %d %s %s", k, app.ID, app.Type, app.Name))
	}
	for k, app := range s.apptype {
		lines = append(lines, fmt.Sprintf("APPTYPE %d %s -> %d %s %s", k.appID, k.typ, app.ID, app.Type, app.Name))
	}
	for k, c := range s.command {
		lines = append(lines, fmt.Sprintf("CMD %d %d -> %s %s req[%s] ans[%s]", k.appID, k.code, c.Name, c.Short,
			rules(c.Request.Rule), rules(c.Answer.Rule)))
	}
	for k, a := range s.avpcode {
		lines = append(lines, fmt.Sprintf("CODE %d %d %s -> %s", k.appID, k.code, vendor(k.vendorID), sig(a)))
	}
	for k, a := range s.avpname {
		lines = append(lines, fmt.Sprintf("NAME %d %s %s -> %s", k.appID, k.name, vendor(k.vendorID), sig(a)))
	}
	for k, a := range s.regname {
		lines = append(lines, fmt.Sprintf("REGNAME %d %s -> %s", k.appID, k.name, sig(a)))
	}
	sort.Strings(lines)
	return lines
}

func diffDumps(t *testing.T, label string, have, want []string) {
	t.Helper()
	if slices.Equal(have, want) {
		return
	}
	haveSet := make(map[string]bool, len(have))
	for _, l := range have {
		haveSet[l] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, l := range want {
		wantSet[l] = true
	}
	n := 0
	for _, l := range want {
		if !haveSet[l] && n < 20 {
			t.Errorf("%s: missing %s", label, l)
			n++
		}
	}
	for _, l := range have {
		if !wantSet[l] && n < 40 {
			t.Errorf("%s: unexpected %s", label, l)
			n++
		}
	}
	t.Fatalf("%s: %d entries, want %d", label, len(have), len(want))
}

// bundledConstants returns the Bundled constants declared in bundled.go,
// by value, with their doc comments.
func bundledConstants(t *testing.T) map[Bundled]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "bundled.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	consts := make(map[Bundled]string)
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Bundled" {
				continue
			}
			for i, name := range vs.Names {
				lit := vs.Values[i].(*ast.BasicLit)
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if vs.Doc == nil {
					t.Errorf("%s has no doc comment", name.Name)
					continue
				}
				consts[Bundled(value)] = name.Name + " " + vs.Doc.Text()
			}
		}
	}
	return consts
}

// TestBundledConstants keeps the named Bundled values and the embedded XML
// files in step: a file without a name, or a name without a file, fails.
func TestBundledConstants(t *testing.T) {
	consts := bundledConstants(t)
	all := AllBundled()
	if !slices.IsSorted(all) {
		t.Errorf("AllBundled() = %v, not in file name order", all)
	}
	for _, b := range all {
		if _, named := consts[b]; !named {
			t.Errorf("embedded dictionary %s has no Bundled constant", b)
		}
		if path.Ext(string(b)) != ".xml" {
			t.Errorf("embedded dictionary %s is not an XML file", b)
		}
	}
	for b := range consts {
		if !slices.Contains(all, b) {
			t.Errorf("Bundled constant %s has no embedded file", b)
		}
	}
	if len(all) == 0 {
		t.Fatal("no bundled dictionaries")
	}
}

// TestBundledDependencies checks each dictionary against its documented
// dependencies: they are exactly the other dictionaries declaring its
// applications or the ancestor applications its lookups reach
// (parentAppIds), and with them its command and Grouped AVP grammars
// resolve.
func TestBundledDependencies(t *testing.T) {
	consts := bundledConstants(t)
	nameOf := make(map[string]Bundled)
	declares := make(map[uint32][]Bundled) // application → dictionaries declaring it
	for b, doc := range consts {
		nameOf[strings.Fields(doc)[0]] = b
		for _, app := range New(b).Apps() {
			declares[app.ID] = append(declares[app.ID], b)
		}
	}
	buildsOn := regexp.MustCompile(`It\s+builds\s+on\s+([^.]*)\.`)
	for b, doc := range consts {
		t.Run(string(b), func(t *testing.T) {
			want := make(map[Bundled]bool)
			for _, app := range New(b).Apps() {
				ancestors, err := ancestorApps(app.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range append(ancestors, app.ID) {
					for _, d := range declares[id] {
						if d != b {
							want[d] = true
						}
					}
				}
			}
			documented := make(map[Bundled]bool)
			if m := buildsOn.FindStringSubmatch(doc); m != nil {
				for _, name := range strings.FieldsFunc(strings.ReplaceAll(m[1], " and ", ","), func(r rune) bool {
					return r == ',' || r == ' ' || r == '\n'
				}) {
					d, ok := nameOf[name]
					if !ok {
						t.Fatalf("documented dependency %q is not a Bundled constant", name)
					}
					documented[d] = true
				}
			}
			if !maps.Equal(documented, want) {
				t.Errorf("documented dependencies %v, lookup scope needs %v", slices.Sorted(maps.Keys(documented)), slices.Sorted(maps.Keys(want)))
			}
			selection := append(slices.Collect(maps.Keys(want)), b)
			p := New(selection...)
			for _, app := range New(b).Apps() {
				for _, missing := range unresolvedRules(p.Snapshot(), app) {
					t.Errorf("New(%v): %s", selection, missing)
				}
			}
		})
	}
}

// unresolvedRules lists the rules of app's commands and of the Grouped AVPs
// they reach that do not resolve in s's lookup scope for app.
func unresolvedRules(s *Snapshot, app *App) []string {
	visited := make(map[string]bool)
	var missing []string
	var check func(string, []*Rule)
	check = func(owner string, rules []*Rule) {
		for _, rule := range rules {
			if rule.AVP == "AVP" { // Diameter's arbitrary AVP wildcard.
				continue
			}
			avp, err := s.FindAVP(app.ID, rule.AVP)
			if err != nil {
				missing = append(missing, fmt.Sprintf("app %d: unresolved AVP %q (via %s)", app.ID, rule.AVP, owner))
				continue
			}
			if avp.Data.TypeName == "Grouped" && !visited[avp.Name] {
				visited[avp.Name] = true
				check(owner+"/"+avp.Name, avp.Data.Rule)
			}
		}
	}
	for _, cmd := range app.Command {
		check(cmd.Name+" request", cmd.Request.Rule)
		check(cmd.Name+" answer", cmd.Answer.Rule)
	}
	for _, avp := range app.AVP {
		if avp.Data.TypeName == "Grouped" && !visited[avp.Name] {
			visited[avp.Name] = true
			check(avp.Name, avp.Data.Rule)
		}
	}
	return missing
}

// TestDefaultMatchesBundledFiles compares Default with Parsers loading the
// same XML files from disk, all at once and one at a time.
func TestDefaultMatchesBundledFiles(t *testing.T) {
	var files []string
	for _, b := range AllBundled() {
		files = append(files, path.Join("bundled", string(b)))
	}
	together, err := NewParser(files...)
	if err != nil {
		t.Fatal(err)
	}
	oneByOne, err := NewParser()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := oneByOne.LoadFile(f); err != nil {
			t.Fatal(err)
		}
	}
	want := dumpSnapshot(Default.Snapshot())
	diffDumps(t, "NewParser(files...)", dumpSnapshot(together.Snapshot()), want)
	diffDumps(t, "LoadFile one by one", dumpSnapshot(oneByOne.Snapshot()), want)
	diffDumps(t, "New(AllBundled()...)", dumpSnapshot(New(AllBundled()...).Snapshot()), want)
	if !Default.Strict() || Default.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Fatalf("Default policy: strict %t, depth %d", Default.Strict(), Default.MaxGroupedDepth())
	}
}

func TestNewSelectsOnlyTheGivenDictionaries(t *testing.T) {
	const gx = 16777238
	p := New(Base, Gx)
	var apps []uint32
	for _, app := range p.Apps() {
		apps = append(apps, app.ID)
	}
	if want := []uint32{0, 3, gx}; !slices.Equal(apps, want) {
		t.Fatalf("applications = %v, want %v", apps, want)
	}
	if _, err := p.App(4); err == nil {
		t.Error("application 4 is supported without CreditControl or RoRf")
	}
	if _, err := p.FindCommand(gx, 272); err != nil {
		t.Errorf("Gx CCR: %v", err)
	}
	if avp, err := p.FindAVPByCode(gx, 1001, 10415); err != nil || avp.Name != "Charging-Rule-Install" {
		t.Errorf("Gx Charging-Rule-Install = %v, %v", avp, err)
	}
	if avp, err := p.FindAVPByCode(gx, 263, 0); err != nil || avp.Name != "Session-Id" {
		t.Errorf("base Session-Id in Gx = %v, %v", avp, err)
	}
	// AVPs of dictionaries that were not selected are unknown, also to Gx
	// which would inherit them from application 4.
	for _, tc := range []struct {
		app, code, vendor uint32
	}{
		{4, 461, 0},             // Service-Context-Id, CreditControl
		{gx, 461, 0},            // the same, through Gx's parent
		{1, 2, 0},               // User-Password, NASREQ
		{16777251, 1407, 10415}, // Visited-PLMN-Id, S6a
	} {
		if avp, err := p.FindAVPByCode(tc.app, tc.code, tc.vendor); err == nil {
			t.Errorf("app %d code %d vendor %d resolves to %s", tc.app, tc.code, tc.vendor, avp.Name)
		}
	}
	s := p.Snapshot()
	for idx, avp := range s.avpcode {
		if !slices.Contains([]uint32{0, 3, gx}, avp.App.ID) {
			t.Errorf("index %v holds %s of application %d", idx, avp.Name, avp.App.ID)
		}
	}
}

func TestNewIgnoresOrderAndDuplicates(t *testing.T) {
	want := dumpSnapshot(New(Base, CreditControl, RoRf).Snapshot())
	diffDumps(t, "reordered", dumpSnapshot(New(RoRf, Base, CreditControl, RoRf, Base).Snapshot()), want)
}

func TestNewWithoutDictionaries(t *testing.T) {
	p := New()
	if apps := p.Apps(); len(apps) != 0 {
		t.Fatalf("Apps() = %v", apps)
	}
	if !p.Strict() || p.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Fatalf("policy: strict %t, depth %d", p.Strict(), p.MaxGroupedDepth())
	}
	if avp, err := p.FindAVPByCode(0, 263, 0); err == nil || avp.Name != "Unknown-263-0" {
		t.Fatalf("FindAVPByCode = %v, %v", avp, err)
	}
}

func TestNewPanicsOnUnknownDictionary(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "not a bundled dictionary") {
			t.Fatalf("recover() = %v", r)
		}
	}()
	New(Base, Bundled("missing.xml"))
}

// RFC 6733 §§4.1 and 4.5 reserve P; the base AVP table has no P column.
func TestBundledBaseAVPFlagRules(t *testing.T) {
	base := New(Base)
	for _, b := range AllBundled() {
		data, err := bundledFS.ReadFile("bundled/" + string(b))
		if err != nil {
			t.Fatal(err)
		}
		var f File
		if err := xml.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		for _, app := range f.App {
			for _, a := range app.AVP {
				_, baseErr := base.FindAVPWithVendor(0, a.Code, a.VendorID)
				if baseErr == nil && (strings.Contains(a.Must, "P") || strings.Contains(a.MustNot, "P")) {
					t.Errorf("%s: %s has obsolete P constraint", b, a.Name)
				}
			}
		}
	}
}
