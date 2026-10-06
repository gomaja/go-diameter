package dict

import (
	"bytes"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestStrictDictionarySchemaMatchesSkel derives the elements and attributes
// that the skel.go types decode from their xml tags, and requires the strict
// loader's schema to list exactly those.
func TestStrictDictionarySchemaMatchesSkel(t *testing.T) {
	elements := map[string]reflect.Type{
		"diameter":    reflect.TypeFor[File](),
		"application": reflect.TypeFor[App](),
		"vendor":      reflect.TypeFor[Vendor](),
		"command":     reflect.TypeFor[Command](),
		"request":     reflect.TypeFor[CommandRule](),
		"answer":      reflect.TypeFor[CommandRule](),
		"avp":         reflect.TypeFor[AVP](),
		"data":        reflect.TypeFor[Data](),
		"item":        reflect.TypeFor[Enum](),
		"rule":        reflect.TypeFor[Rule](),
	}
	if got, want := sortedKeys(dictionaryElements), sortedKeys(elements); !slices.Equal(got, want) {
		t.Fatalf("schema elements = %v; skel.go elements = %v", got, want)
	}
	for name, typ := range elements {
		children, attrs := map[string]bool{}, map[string]bool{}
		for field := range typ.Fields() {
			tag := field.Tag.Get("xml")
			if field.Name == "XMLName" || tag == "" || tag == "-" {
				continue
			}
			tagName, options, _ := strings.Cut(tag, ",")
			if options == "attr" {
				attrs[tagName] = true
				continue
			}
			if options != "" {
				t.Fatalf("%s.%s: unsupported xml tag %q", typ.Name(), field.Name, tag)
			}
			if _, ok := elements[tagName]; !ok {
				t.Fatalf("%s.%s decodes <%s>, which the schema does not define", typ.Name(), field.Name, tagName)
			}
			children[tagName] = true
		}
		schema := dictionaryElements[name]
		if got, want := sortedKeys(schema.children), sortedKeys(children); !slices.Equal(got, want) {
			t.Errorf("<%s> children: schema %v, skel.go %v", name, got, want)
		}
		if got, want := sortedKeys(schema.attrs), sortedKeys(attrs); !slices.Equal(got, want) {
			t.Errorf("<%s> attributes: schema %v, skel.go %v", name, got, want)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestStrictDictionaryXMLNamesAttribute(t *testing.T) {
	for _, tc := range []struct{ old, replacement, want string }{
		{`must="M"`, `must="M" must_not="V"`, `unexpected attribute "must_not" on <avp>`},
		{`name="Supplier"`, `name="Supplier" xmlns:x="urn:foreign" x:extra="x"`, `unexpected attribute "xmlns:x" on <vendor>`},
	} {
		input := strings.Replace(strictXMLSample, tc.old, tc.replacement, 1)
		_, err := parseFile(strings.NewReader(input))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v; want it to contain %s", tc.replacement, err, tc.want)
		}
	}
}

// TestRuleXMLRoundTrip writes rules with encoding/xml and reads them back:
// an unbounded rule must stay unbounded rather than become an explicit
// maximum of zero.
func TestRuleXMLRoundTrip(t *testing.T) {
	rules := []*Rule{
		{AVP: "Unbounded"},
		{AVP: "Absent", Max: 0, MaxSet: true},
		{AVP: "Implicit-Max", Max: 3},
		{AVP: "Explicit-Max", Max: 1, MaxSet: true},
		{AVP: "Fixed-Required", Required: true, Min: 1, Max: 1, MaxSet: true, Fixed: true},
		{AVP: "Negative", Min: -1, Max: -1},
	}
	file := &File{App: []*App{{
		ID: 1, Type: "auth", Name: "Round-Trip",
		AVP: []*AVP{{Name: "Group", Code: 1, Data: Data{TypeName: "Grouped", Rule: rules}}},
	}}}
	var out bytes.Buffer
	if err := xml.NewEncoder(&out).Encode(file); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `avp="Unbounded" max=`) {
		t.Fatalf("unbounded rule written with a maximum: %s", out.String())
	}
	back, err := parseFile(&out)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := back.App[0].AVP[0].Data.Rule
	if len(got) != len(rules) {
		t.Fatalf("reloaded %d rules; want %d", len(got), len(rules))
	}
	for i, want := range rules {
		r := got[i]
		if r.AVP != want.AVP || r.Required != want.Required || r.Min != want.Min ||
			r.Max != want.Max || r.Fixed != want.Fixed || hasMax(r) != hasMax(want) {
			t.Errorf("rule %s reloaded as %+v; want %+v", want.AVP, *r, *want)
		}
	}
}

func hasMax(r *Rule) bool { return r.MaxSet || r.Max != 0 }

// TestRuleValueXML marshals a Rule value, not a pointer: encoding/xml uses
// MarshalXML for both only with a value receiver.
func TestRuleValueXML(t *testing.T) {
	out, err := xml.Marshal(Rule{AVP: "Unbounded"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `<Rule avp="Unbounded"></Rule>`; got != want {
		t.Fatalf("xml.Marshal(Rule) = %s; want %s", got, want)
	}
}

// TestExampleDictionariesLoad loads every dictionary the examples ship, so
// the strict loader cannot reject one without a test failing.
func TestExampleDictionariesLoad(t *testing.T) {
	var files []string
	err := filepath.WalkDir(filepath.Join("..", "..", "examples"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".xml" {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example dictionaries found")
	}
	for _, path := range files {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := New(AllBundled()...).Load(bytes.NewReader(b)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
