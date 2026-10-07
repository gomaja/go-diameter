package dict

import (
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path"
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
		lines = append(lines, fmt.Sprintf("NAME %d %s -> %s", k.appID, k.name, sig(a)))
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

// bundledApps inspects declarations without building an incomplete dictionary
// whose Grouped rules may require the bundle's documented dependencies.
func bundledApps(t *testing.T, b Bundled) []*App {
	t.Helper()
	data, err := bundledFS.ReadFile(path.Join("bundled", string(b)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseFile(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return f.App
}

// TestBundledDependencies derives the exact provider set from the XML rather
// than from the table or prose. Resolve each rule at its nearest application,
// using file name order for definitions shared by multiple bundles.
func TestBundledDependencies(t *testing.T) {
	all := AllBundled()
	apps := make(map[Bundled][]*App)
	providers := make(map[appNameIdx]Bundled)
	for _, b := range all {
		apps[b] = bundledApps(t, b)
		for _, app := range apps[b] {
			for _, avp := range app.AVP {
				providers[appNameIdx{app.ID, avp.Name}] = b
			}
		}
	}
	if len(bundledDependencies) != len(all) {
		t.Errorf("dependency entries = %d, want %d", len(bundledDependencies), len(all))
	}
	for b := range bundledDependencies {
		if !slices.Contains(all, b) {
			t.Errorf("dependency entry for unknown bundle %s", b)
		}
	}
	for _, b := range all {
		t.Run(string(b), func(t *testing.T) {
			want := make(map[Bundled]bool)
			for _, app := range apps[b] {
				ancestors, err := ancestorApps(app.ID)
				if err != nil {
					t.Fatal(err)
				}
				scope := append([]uint32{app.ID}, ancestors...)
				var rules []*Rule
				for _, avp := range app.AVP {
					rules = append(rules, avp.Data.Rule...)
				}
				for _, cmd := range app.Command {
					rules = append(rules, cmd.Request.Rule...)
					rules = append(rules, cmd.Answer.Rule...)
				}
				for _, rule := range rules {
					if rule.AVP == "AVP" {
						continue
					}
					var provider Bundled
					for _, id := range scope {
						if provider = providers[appNameIdx{id, rule.AVP}]; provider != "" {
							break
						}
					}
					if provider == "" {
						t.Fatalf("app %d: no provider for %s", app.ID, rule.AVP)
					}
					if provider != b {
						want[provider] = true
					}
				}
			}
			have := make(map[Bundled]bool)
			deps, ok := bundledDependencies[b]
			if !ok {
				t.Fatal("missing dependency entry")
			}
			for _, d := range deps {
				if have[d] {
					t.Errorf("duplicate dependency %s", d)
				}
				have[d] = true
			}
			if !maps.Equal(have, want) {
				t.Errorf("declared dependencies %v, XML rules need %v", slices.Sorted(maps.Keys(have)), slices.Sorted(maps.Keys(want)))
			}
			p := New(b)
			for _, app := range apps[b] {
				for _, missing := range unresolvedRules(p.Snapshot(), app) {
					t.Error(missing)
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
			avp, err := s.FindAVPByName(app.ID, rule.AVP)
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
// same XML files from disk in one atomic load, including mutual dependencies.
func TestDefaultMatchesBundledFiles(t *testing.T) {
	var files []string
	for _, b := range AllBundled() {
		files = append(files, path.Join("bundled", string(b)))
	}
	together, err := NewParser(files...)
	if err != nil {
		t.Fatal(err)
	}
	want := dumpSnapshot(Default.Snapshot())
	diffDumps(t, "NewParser(files...)", dumpSnapshot(together.Snapshot()), want)
	diffDumps(t, "New(AllBundled()...)", dumpSnapshot(New(AllBundled()...).Snapshot()), want)
	if !Default.Strict() || Default.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Fatalf("Default policy: strict %t, depth %d", Default.Strict(), Default.MaxGroupedDepth())
	}
}

func TestNewSelectsOnlyTheGivenDictionariesAndDependencies(t *testing.T) {
	const cx = 16777216
	p := New(Base, NASREQ, Cx)
	var apps []uint32
	for _, app := range p.Apps() {
		apps = append(apps, app.ID)
	}
	if want := []uint32{0, 3, 1, cx}; !slices.Equal(apps, want) {
		t.Fatalf("applications = %v, want %v", apps, want)
	}
	if _, err := p.App(4); err == nil {
		t.Error("application 4 is supported without CreditControl or RoRf")
	}
	if _, err := p.FindCommand(cx, 300); err != nil {
		t.Errorf("Cx UAR: %v", err)
	}
	if avp, err := p.FindAVP(cx, 601, 10415); err != nil || avp.Name != "Public-Identity" {
		t.Errorf("Cx Public-Identity = %v, %v", avp, err)
	}
	if avp, err := p.FindAVP(cx, 263, 0); err != nil || avp.Name != "Session-Id" {
		t.Errorf("base Session-Id in Cx = %v, %v", avp, err)
	}
	// Unselected dictionaries contribute neither applications nor definitions.
	for _, tc := range []struct {
		app, code, vendor uint32
	}{
		{4, 461, 0},             // Service-Context-Id, CreditControl
		{16777238, 1001, 10415}, // Charging-Rule-Install, Gx
		{16777251, 1407, 10415}, // Visited-PLMN-Id, S6a
	} {
		if avp, err := p.FindAVP(tc.app, tc.code, tc.vendor); err == nil {
			t.Errorf("app %d code %d vendor %d resolves to %s", tc.app, tc.code, tc.vendor, avp.Name)
		}
	}
	for idx, avp := range p.Snapshot().avpcode {
		if !slices.Contains([]uint32{0, 3, 1, cx}, avp.App.ID) {
			t.Errorf("index %v holds %s of application %d", idx, avp.Name, avp.App.ID)
		}
	}
}

func TestNewIgnoresOrderAndDuplicates(t *testing.T) {
	want := dumpSnapshot(New(Base, NASREQ, CreditControl, RoRf).Snapshot())
	diffDumps(t, "reordered", dumpSnapshot(New(RoRf, Base, NASREQ, CreditControl, RoRf, Base).Snapshot()), want)
}

func TestNewWithoutDictionaries(t *testing.T) {
	p := New()
	if apps := p.Apps(); len(apps) != 0 {
		t.Fatalf("Apps() = %v", apps)
	}
	if !p.Strict() || p.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Fatalf("policy: strict %t, depth %d", p.Strict(), p.MaxGroupedDepth())
	}
	if avp, err := p.FindAVP(0, 263, 0); err == nil || avp != nil {
		t.Fatalf("FindAVP = %v, %v", avp, err)
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
				_, baseErr := base.FindAVP(0, a.Code, a.VendorID)
				if baseErr == nil && (strings.Contains(a.Must, "P") || strings.Contains(a.MustNot, "P")) {
					t.Errorf("%s: %s has obsolete P constraint", b, a.Name)
				}
			}
		}
	}
}
