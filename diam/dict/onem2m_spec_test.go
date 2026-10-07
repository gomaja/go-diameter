package dict

import (
	"encoding/json"
	"os"
	"testing"
)

func loadOneM2MSpec(t *testing.T) []rxAVPSpec {
	t.Helper()
	b, err := os.ReadFile("testdata/onem2m_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ AVPs []rxAVPSpec }
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.AVPs) != 23 {
		t.Fatalf("oneM2M fixture has %d AVPs, want 23", len(s.AVPs))
	}
	for i, a := range s.AVPs {
		if a.Code != uint32(1000+i) || a.Vendor != 45687 || a.Section == "" {
			t.Fatalf("incomplete source identity at row %d: %+v", i, a)
		}
	}
	return s.AVPs
}

// oneM2M TS-0004 V5.2.0 Table A.4-1, §§A.5.1–A.5.32;
// TS 32.299 V19.0.0 §7.5 imports the AVPs into both charging applications.
func TestOneM2MAVPSpec(t *testing.T) {
	for _, want := range loadOneM2MSpec(t) {
		t.Run(want.Name, func(t *testing.T) {
			for _, dictionary := range []*Parser{Default, New(RoRf), New(CreditControl)} {
				for _, app := range []uint32{3, 4} {
					a, err := dictionary.FindAVP(app, want.Code, want.Vendor)
					if err != nil {
						t.Fatal(err)
					}
					rxCheckAVP(t, a, want)
					named, err := dictionary.FindAVPByName(app, want.Name)
					if err != nil || named != a {
						t.Fatalf("name lookup differs for %s in app %d: %v", want.Name, app, err)
					}
				}
			}
		})
	}
}

// Table slips remain recorded, even though the introducing CRs resolve the
// implementation choice in favour of each AVP's explicit defining clause.
func TestRoRfResolvedTableSlips(t *testing.T) {
	b, err := os.ReadFile("testdata/rorf_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Conflicts []struct {
			Name, Choice, Status, Reason string
			TableType                    string `json:"table_type"`
			ClauseType                   string `json:"clause_type"`
		} `json:"source_conflicts"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Conflicts) != 3 {
		t.Fatalf("table-slip count %d, want 3", len(s.Conflicts))
	}
	for _, c := range s.Conflicts {
		a, err := Default.FindAVPByName(4, c.Name)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status != "resolved-table-slip" || c.Reason == "" || c.TableType == c.ClauseType || c.Choice != c.ClauseType || a.Data.TypeName != c.ClauseType {
			t.Errorf("unresolved or incorrect table slip for %s: %+v, dictionary type %s", c.Name, c, a.Data.TypeName)
		}
	}
}

// oneM2M TS-0004 V5.2.0 §A.5.17 reserves ranges without assigning values.
func TestOneM2MProtocolReservedRanges(t *testing.T) {
	for _, value := range []int32{4, 99, 100, 199} {
		if e, err := Default.Enum(4, 1013, 45687, value); err == nil {
			t.Errorf("range boundary %d became enumerator %s", value, e.Name)
		}
	}
}
