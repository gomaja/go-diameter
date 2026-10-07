package dict

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TS 29.272 V19.6.0 §7.3.1 and TS 29.273 V19.2.0 §8.2.3.0
// distinguish application requirements from incidental inherited extensions.
// The fixture records the defining clauses and each application's applicability.
func TestSMSInheritedApplicationSpec(t *testing.T) {
	b, err := os.ReadFile("testdata/sms_inheritance_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Applications        []uint32
		Definitions         []smsDefinitionSpec
		SWxLocalDefinitions []smsDefinitionSpec `json:"swx_local_definitions"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Applications) != 2 || len(s.Definitions) != 12 {
		t.Fatal("incomplete inheritance audit")
	}
	for _, app := range s.Applications {
		for _, w := range s.Definitions {
			if flags, ok := w.ApplicationFlags[app]; ok {
				w.Must, w.May, w.MustNot = flags.Must, flags.May, flags.MustNot
			}
			t.Run(fmt.Sprintf("%d/%s", app, w.Name), func(t *testing.T) {
				smsCheckInheritedDefinition(t, app, w)
			})
		}
	}
	want := []string{"GMLC-Address", "User-CSG-Information", "eNodeB-ID", "External-Identifier"}
	if len(s.SWxLocalDefinitions) != len(want) {
		t.Fatal("incomplete SWx local definition audit")
	}
	for i, w := range s.SWxLocalDefinitions {
		if w.Name != want[i] {
			t.Fatalf("SWx definition %d: got %s, want %s", i, w.Name, want[i])
		}
		t.Run("SWx-local/"+w.Name, func(t *testing.T) {
			smsCheckInheritedDefinition(t, 16777265, w)
		})
	}
}

// The fixture cites each defining table and clause. A reused AVP's complete
// definition is checked even when it is only an optional inherited extension.
func smsCheckInheritedDefinition(t *testing.T, app uint32, w smsDefinitionSpec) {
	t.Helper()
	a, err := Default.FindAVP(app, w.Code, w.Vendor)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := Default.FindAVPByName(app, w.Name)
	if err != nil || a != byName || a.Name != w.Name || a.Data.TypeName != w.Type {
		t.Fatalf("identity/type mismatch: %+v, %v", a, err)
	}
	if gxFlags(a.Must) != gxFlags(w.Must) || gxFlags(a.May) != gxFlags(w.May) || gxFlags(a.MustNot) != gxFlags(w.MustNot) || strings.ToUpper(a.MayEncrypt) != w.MayEncrypt {
		t.Errorf("flags %q/%q/%q/%q, want %q/%q/%q/%q", a.Must, a.May, a.MustNot, a.MayEncrypt, w.Must, w.May, w.MustNot, w.MayEncrypt)
	}
	if len(a.Data.Enum) != len(w.Items) {
		t.Errorf("enum count %d, want %d", len(a.Data.Enum), len(w.Items))
	}
	for _, e := range a.Data.Enum {
		if e.Name != w.Items[strconv.Itoa(int(e.Code))] {
			t.Errorf("enum %d=%s differs from source", e.Code, e.Name)
		}
	}
	smsCheckRules(t, a.Data.Rule, w.Rules)
}
