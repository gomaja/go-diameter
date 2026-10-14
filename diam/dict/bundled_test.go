package dict_test

import (
	"encoding/xml"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/all"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
)

func TestApplicationSelectionsMatchManifest(t *testing.T) {
	var expected []string
	for _, selection := range applicationSelections() {
		expected = append(expected, selection.name)
	}
	if !slices.IsSorted(expected) {
		t.Fatal("application fixture is not in canonical filename order")
	}
	if actual := sourceNames(t); !slices.Equal(actual, expected) {
		t.Fatalf("manifest=%v, want %v", actual, expected)
	}
	names, err := dict.SourceNamesForTesting(all.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, expected) {
		t.Fatalf("all selection=%v, want %v", names, expected)
	}
}

func TestApplicationDependencyClosures(t *testing.T) {
	for _, selection := range applicationSelections() {
		t.Run(selection.name, func(t *testing.T) {
			names, err := dict.SourceNamesForTesting(selection.dictionary)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(names, selection.sources) {
				t.Fatalf("sources=%v, want %v", names, selection.sources)
			}
			p := newTestParser(t, selection.dictionary)
			for _, app := range sourceApps(t, selection.name) {
				for _, missing := range unresolvedRules(p.Snapshot(), app) {
					t.Error(missing)
				}
			}
		})
	}
}

func unresolvedRules(s *dict.Snapshot, app *dict.App) []string {
	visited := make(map[string]bool)
	var missing []string
	var check func(string, []*dict.Rule)
	check = func(owner string, rules []*dict.Rule) {
		for _, r := range rules {
			if r.AVP == "AVP" {
				continue
			}
			a, err := s.FindAVPByName(app.ID, r.AVP)
			if err != nil {
				missing = append(missing, owner+": unresolved "+r.AVP)
				continue
			}
			if a.Data.TypeName == "Grouped" && !visited[a.Name] {
				visited[a.Name] = true
				check(owner+"/"+a.Name, a.Data.Rule)
			}
		}
	}
	for _, c := range app.Command {
		check(c.Name+" request", c.Request.Rule)
		check(c.Name+" answer", c.Answer.Rule)
	}
	for _, a := range app.AVP {
		if a.Data.TypeName == "Grouped" && !visited[a.Name] {
			visited[a.Name] = true
			check(a.Name, a.Data.Rule)
		}
	}
	return missing
}

func TestAllMatchesManifestFiles(t *testing.T) {
	reference := newAllTestParser(t)

	var files []string
	for _, name := range sourceNames(t) {
		files = append(files, sourcePath(t, name))
	}
	together, err := dict.NewParser(files...)
	if err != nil {
		t.Fatal(err)
	}
	diffDumps(t, "all versus files", dumpSnapshot(reference.Snapshot()), dumpSnapshot(together.Snapshot()))
	if !reference.Strict() || reference.MaxGroupedDepth() != dict.DefaultMaxGroupedDepth {
		t.Fatal("unexpected all policy")
	}
}

func TestNewSelectsOnlyTheGivenDictionariesAndDependencies(t *testing.T) {
	const cxApp = 16777216
	p := newTestParser(t, dict.Base(), nasreq.Dictionary(), cx.Dictionary())
	var apps []uint32
	for _, app := range p.Apps() {
		apps = append(apps, app.ID)
	}
	if want := []uint32{0, 3, 1, cxApp}; !slices.Equal(apps, want) {
		t.Fatalf("applications=%v, want %v", apps, want)
	}
	if _, err := p.App(4); err == nil {
		t.Error("unselected Credit-Control supported")
	}
	if _, err := p.FindCommand(cxApp, 300); err != nil {
		t.Error(err)
	}
	for _, tc := range []struct {
		code, vendor uint32
		name         string
	}{{601, 10415, "Public-Identity"}, {263, 0, "Session-Id"}} {
		a, err := p.FindAVP(cxApp, tc.code, tc.vendor)
		if err != nil || a.Name != tc.name {
			t.Errorf("Cx %s=%v,%v", tc.name, a, err)
		}
	}
	for _, tc := range []struct{ app, code, vendor uint32 }{{4, 461, 0}, {16777238, 1001, 10415}, {16777251, 1407, 10415}} {
		if a, err := p.FindAVP(tc.app, tc.code, tc.vendor); err == nil {
			t.Errorf("unselected app %d resolves %s", tc.app, a.Name)
		}
	}
	for idx, a := range dict.CodeIndexForTesting(p.Snapshot()) {
		if !slices.Contains([]uint32{0, 3, 1, cxApp}, a.App.ID) {
			t.Errorf("index %v holds %s of unselected app %d", idx, a.Name, a.App.ID)
		}
	}
}
func TestNewIgnoresOrderAndDuplicates(t *testing.T) {
	want := dumpSnapshot(newTestParser(t, dict.Base(), nasreq.Dictionary(), creditcontrol.Dictionary(), rorf.Dictionary()).Snapshot())
	diffDumps(t, "reordered", dumpSnapshot(newTestParser(t, rorf.Dictionary(), dict.Base(), nasreq.Dictionary(), creditcontrol.Dictionary(), rorf.Dictionary(), dict.Base()).Snapshot()), want)
	names, err := dict.SourceNamesForTesting(rorf.Dictionary(), creditcontrol.Dictionary(), rorf.Dictionary(), dict.Base())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"base.xml", "credit_control.xml", "network_access_server.xml", "tgpp_ro_rf.xml"}; !slices.Equal(names, want) {
		t.Fatalf("deduplicated sources=%v, want %v", names, want)
	}
}
func TestNewWithoutDictionaries(t *testing.T) {
	p := newTestParser(t)
	if apps := p.Apps(); len(apps) != 0 {
		t.Fatalf("Apps=%v", apps)
	}
	if !p.Strict() || p.MaxGroupedDepth() != dict.DefaultMaxGroupedDepth {
		t.Fatal("unexpected empty policy")
	}
	if a, err := p.FindAVP(0, 263, 0); err == nil || a != nil {
		t.Fatalf("FindAVP=%v,%v", a, err)
	}
}
func TestNewReportsInvalidDictionary(t *testing.T) {
	p, err := dict.New(dict.Base(), dict.Dictionary{})
	if p != nil || err == nil {
		t.Fatalf("New invalid=%v,%v", p, err)
	}
	if p, err := dict.New(dict.Embedded("missing.xml", "invalid")); p != nil || err == nil {
		t.Fatalf("New malformed=%v,%v", p, err)
	}
	if p, err := dict.New(dict.Embedded("base.xml", "<diameter/>"), dict.Base()); p != nil || !errors.Is(err, dict.ErrDictionaryConflict) {
		t.Fatalf("New conflicting=%v,%v", p, err)
	}
}

// RFC 6733 §§4.1 and 4.5 reserve P; the base AVP table has no P column.
func TestShippedBaseAVPFlagRules(t *testing.T) {
	base := newTestParser(t, dict.Base())
	for _, name := range sourceNames(t) {
		data, err := os.ReadFile(sourcePath(t, name))
		if err != nil {
			t.Fatal(err)
		}
		var file dict.File
		if err := xml.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		for _, app := range file.App {
			for _, a := range app.AVP {
				_, baseErr := base.FindAVP(0, a.Code, a.VendorID)
				if baseErr == nil && (strings.Contains(a.Must, "P") || strings.Contains(a.MustNot, "P")) {
					t.Errorf("%s: %s has obsolete P constraint", name, a.Name)
				}
			}
		}
	}
}

// Derive prerequisite providers from the raw XML declarations independently of
// the public descriptors. A rule resolves at the nearest declared application;
// canonical source order chooses providers of shared definitions.
func TestApplicationDependenciesMatchXMLProviders(t *testing.T) {
	type appName struct {
		app  uint32
		name string
	}
	sources := sourceNames(t)
	apps := make(map[string][]*dict.App)
	providers := make(map[appName]string)
	parents := make(map[uint32][]uint32)
	for _, name := range sources {
		apps[name] = sourceApps(t, name)
		for _, app := range apps[name] {
			for _, parent := range app.Inherits {
				if !slices.Contains(parents[app.ID], parent) {
					parents[app.ID] = append(parents[app.ID], parent)
				}
			}
			for _, a := range app.AVP {
				providers[appName{app.ID, a.Name}] = name
			}
		}
	}
	scope := func(app uint32) []uint32 {
		ordered := []uint32{app}
		seen := map[uint32]bool{app: true}
		for i := 0; i < len(ordered); i++ {
			for _, parent := range parents[ordered[i]] {
				if parent != 0 && !seen[parent] {
					seen[parent] = true
					ordered = append(ordered, parent)
				}
			}
		}
		if app != 0 {
			ordered = append(ordered, 0)
		}
		return ordered
	}
	required := make(map[string][]string)
	for _, name := range sources {
		for _, app := range apps[name] {
			var rules []*dict.Rule
			for _, a := range app.AVP {
				rules = append(rules, a.Data.Rule...)
			}
			for _, c := range app.Command {
				rules = append(rules, c.Request.Rule...)
				rules = append(rules, c.Answer.Rule...)
			}
			for _, rule := range rules {
				if rule.AVP == "AVP" {
					continue
				}
				provider := ""
				for _, id := range scope(app.ID) {
					if provider = providers[appName{id, rule.AVP}]; provider != "" {
						break
					}
				}
				if provider == "" {
					t.Fatalf("source %s app %d: no provider for %s", name, app.ID, rule.AVP)
				}
				if provider != name && !slices.Contains(required[name], provider) {
					required[name] = append(required[name], provider)
				}
			}
		}
	}
	for _, selection := range applicationSelections() {
		t.Run(selection.name, func(t *testing.T) {
			reached := map[string]bool{}
			pending := []string{selection.name}
			for len(pending) > 0 {
				name := pending[len(pending)-1]
				pending = pending[:len(pending)-1]
				if !reached[name] {
					reached[name] = true
					pending = append(pending, required[name]...)
				}
			}
			var expected []string
			for _, name := range sources {
				if reached[name] {
					expected = append(expected, name)
				}
			}
			actual, err := dict.SourceNamesForTesting(selection.dictionary)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(actual, expected) {
				t.Fatalf("descriptor sources=%v, XML rule providers require %v", actual, expected)
			}
		})
	}
}

func TestShippedParentAppIDsAcyclic(t *testing.T) {
	parents := make(map[uint32][]uint32)
	for _, name := range sourceNames(t) {
		for _, app := range sourceApps(t, name) {
			parents[app.ID] = append(parents[app.ID], app.Inherits...)
		}
	}
	active, complete := make(map[uint32]bool), make(map[uint32]bool)
	var visit func(uint32)
	visit = func(id uint32) {
		if active[id] {
			t.Fatalf("shipped parent graph cycles through application %d", id)
		}
		if complete[id] {
			return
		}
		active[id] = true
		for _, parent := range parents[id] {
			visit(parent)
		}
		active[id] = false
		complete[id] = true
	}
	for id := range parents {
		visit(id)
	}
	// Construction exercises the parser's own parent validation as well.
	_ = newTestParser(t, all.Dictionary())
}
