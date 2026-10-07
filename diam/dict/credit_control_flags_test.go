package dict

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

// RFC 8506 (March 2019) §8, AVP flag table, pp. 60–61. The fixture is
// transcribed from the specification, independently of the bundled XML.
// P is absent from this table; RFC 6733 (October 2012) §4.1 says senders
// SHOULD clear it, which does not make it a MUST NOT flag.
func TestCreditControlAVPFlagsRFC8506(t *testing.T) {
	type entry struct {
		Name    string
		Code    uint32
		Section string
		Must    string
		May     string
		MustNot string `json:"must_not"`
	}
	var fixture struct{ AVPs []entry }
	data, err := os.ReadFile("testdata/rfc8506_avp_flags.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.AVPs) != 68 {
		t.Fatalf("RFC 8506 §8 fixture has %d AVPs, want 68", len(fixture.AVPs))
	}
	wantByCode := make(map[uint32]entry, len(fixture.AVPs))
	for _, want := range fixture.AVPs {
		if _, exists := wantByCode[want.Code]; exists {
			t.Fatalf("duplicate fixture AVP code %d", want.Code)
		}
		wantByCode[want.Code] = want
	}
	for _, name := range []string{"credit_control.xml", "gx_credit_control.xml"} {
		t.Run(name, func(t *testing.T) {
			data, err := bundledFS.ReadFile("bundled/" + name)
			if err != nil {
				t.Fatal(err)
			}
			var file File
			if err := xml.Unmarshal(data, &file); err != nil {
				t.Fatal(err)
			}
			seen := make(map[uint32]bool)
			for _, app := range file.App {
				for _, avp := range app.AVP {
					want, found := wantByCode[avp.Code]
					if avp.VendorID != 0 || !found {
						continue
					}
					// TS 29.212 V20.0.0 Table 5.4.0.1 and Note 5 override
					// the M bit of usage-monitoring units and their members.
					if name == "gx_credit_control.xml" {
						switch avp.Code {
						case 412, 414, 420, 421, 431, 446:
							want.Must, want.May, want.MustNot = "", "", "M,V"
						}
					}
					seen[avp.Code] = true
					t.Run(want.Name, func(t *testing.T) {
						if avp.Name != want.Name {
							t.Errorf("AVP %d/0 name = %q, want %q", avp.Code, avp.Name, want.Name)
						}
						if strings.Trim(avp.Must, "-") != strings.Trim(want.Must, "-") || strings.Trim(avp.May, "-") != strings.Trim(want.May, "-") || strings.Trim(avp.MustNot, "-") != strings.Trim(want.MustNot, "-") {
							t.Errorf("RFC 8506 §8 table (%s, §%s): must/may/must-not = %q/%q/%q, want %q/%q/%q",
								want.Name, want.Section, avp.Must, avp.May, avp.MustNot, want.Must, want.May, want.MustNot)
						}
					})
				}
			}
			if name == "credit_control.xml" {
				for _, want := range fixture.AVPs {
					if !seen[want.Code] {
						t.Errorf("missing RFC 8506 AVP %s (%d/0)", want.Name, want.Code)
					}
				}
			}
			t.Logf("checked %d locally defined RFC 8506 AVPs", len(seen))
		})
	}
}
