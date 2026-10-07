package dict

import (
	"bytes"
	"encoding/xml"
	"io"
	"io/fs"
	"sort"
	"testing"
)

// The same (Vendor-Id, AVP code) carries one Enumerated value registry even
// when several bundled applications declare the AVP independently.
func TestBundledEnumerationConsistency(t *testing.T) {
	type key struct{ vendor, code uint32 }
	type definition struct {
		file, name string
		items      map[int32]string
	}
	type avpXML struct {
		Name     string `xml:"name,attr"`
		Code     uint32 `xml:"code,attr"`
		VendorID uint32 `xml:"vendor-id,attr"`
		Data     struct {
			Type  string `xml:"type,attr"`
			Items []struct {
				Code int32  `xml:"code,attr"`
				Name string `xml:"name,attr"`
			} `xml:"item"`
		} `xml:"data"`
	}

	entries, err := fs.ReadDir(bundledFS, "bundled")
	if err != nil {
		t.Fatal(err)
	}
	definitions := make(map[key][]definition)
	// Add a key only for a specification-backed application exception, with
	// the document, version, and clause in its reason. Stale entries fail.
	allowlist := map[key]string{}
	usedAllowlist := make(map[key]bool)
	for k, reason := range allowlist {
		if reason == "" {
			t.Errorf("enum (%d,%d) has an empty allowlist reason", k.vendor, k.code)
		}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		contents, err := fs.ReadFile(bundledFS, "bundled/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		decoder := xml.NewDecoder(bytes.NewReader(contents))
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", entry.Name(), err)
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "avp" {
				continue
			}
			var avp avpXML
			if err := decoder.DecodeElement(&avp, &start); err != nil {
				t.Fatalf("%s: %v", entry.Name(), err)
			}
			if avp.Data.Type != "Enumerated" {
				continue
			}
			items := make(map[int32]string, len(avp.Data.Items))
			for _, item := range avp.Data.Items {
				if old, exists := items[item.Code]; exists {
					t.Errorf("%s: %s (%d,%d) repeats value %d (%q, %q)", entry.Name(), avp.Name, avp.VendorID, avp.Code, item.Code, old, item.Name)
				}
				items[item.Code] = item.Name
			}
			k := key{avp.VendorID, avp.Code}
			definitions[k] = append(definitions[k], definition{entry.Name(), avp.Name, items})
		}
	}

	keys := make([]key, 0, len(definitions))
	for k := range definitions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].vendor != keys[j].vendor {
			return keys[i].vendor < keys[j].vendor
		}
		return keys[i].code < keys[j].code
	})
	for _, k := range keys {
		defs := definitions[k]
		if len(defs) < 2 {
			continue
		}
		codes := make(map[int32]bool)
		for _, def := range defs {
			for code := range def.items {
				codes[code] = true
			}
		}
		ordered := make([]int, 0, len(codes))
		for code := range codes {
			ordered = append(ordered, int(code))
		}
		sort.Ints(ordered)
		for _, code := range ordered {
			first, firstPresent := defs[0].items[int32(code)]
			for _, def := range defs[1:] {
				if got, present := def.items[int32(code)]; present != firstPresent || got != first {
					if _, allowed := allowlist[k]; allowed {
						usedAllowlist[k] = true
						continue
					}
					t.Errorf("enum (%d,%d) value %d: %s/%s=%q; %s/%s=%q", k.vendor, k.code, code, defs[0].file, defs[0].name, first, def.file, def.name, got)
				}
			}
		}
	}
	for k := range allowlist {
		if !usedAllowlist[k] {
			t.Errorf("enum (%d,%d) allowlist entry is stale", k.vendor, k.code)
		}
	}
}

// TS 29.273 V19.2.0 Table 8.2.3.0/2 Note 1 keeps the defining AVP's
// flags unless SWx explicitly overrides its M bit.
func TestSWxReusedEnumerationsInheritDefinitions(t *testing.T) {
	p := Default
	for _, tc := range []struct {
		name                           string
		code, parentApp                uint32
		must, may, mustNot, mayEncrypt string
	}{
		// TS 29.212 V20.0.0 Table 5.3.0.1; TS 29.273 V19.2.0 §8.2.3.0.
		{"QoS-Class-Identifier", 1028, 4, "M,V", "P", "", "Y"},
		// TS 29.272 V19.6.0 Table 7.3.1/1; TS 29.273 V19.2.0 §8.2.3.0.
		{"Trace-Depth", 1462, 16777251, "M,V", "", "", "N"},
		{"SIPTO-Permission", 1613, 16777251, "V", "", "M", "N"},
		{"LIPA-Permission", 1618, 16777251, "V", "", "M", "N"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, err := p.FindAVP(tc.parentApp, tc.code, 10415)
			if err != nil {
				t.Fatal(err)
			}
			swx, err := p.FindAVP(16777265, tc.code, 10415)
			if err != nil {
				t.Fatal(err)
			}
			if swx != parent {
				t.Errorf("SWx %s has a separate definition; want inherited %s flags and values", tc.name, tc.name)
			}
			if swx.Must != tc.must || swx.May != tc.may || swx.MustNot != tc.mustNot || swx.MayEncrypt != tc.mayEncrypt {
				t.Errorf("SWx %s flags = %q/%q/%q/%q, want %q/%q/%q/%q", tc.name,
					swx.Must, swx.May, swx.MustNot, swx.MayEncrypt,
					tc.must, tc.may, tc.mustNot, tc.mayEncrypt)
			}
		})
	}
}

func TestRxOCReportTypeInheritsBase(t *testing.T) {
	base, err := Default.FindAVP(0, 626, 0)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := Default.FindAVP(16777236, 626, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rx != base {
		t.Error("Rx OC-Report-Type has a separate definition; want inherited RFC 7683 §7.6 / RFC 8581 §7.2.1 values and flags")
	}
}

func TestReusedEnumNameTypography(t *testing.T) {
	// TS 29.212 V20.0.0 §5.3.31 assigns value 2; TS 29.214 V20.0.0
	// Annex E.6 confirms the TRUSTED-N3GA spelling without an internal space.
	for _, app := range []uint32{4, 16777236, 16777251, 16777265} {
		item, err := Default.Enum(app, 1032, 10415, 2)
		if err != nil {
			t.Fatal(err)
		}
		if item.Name != "TRUSTED-N3GA" {
			t.Errorf("application %d RAT-Type 2 = %q, want TRUSTED-N3GA", app, item.Name)
		}
	}
	// TS 29.272 V19.6.0 §7.3.135 prints an accidental space before
	// the underscore; names in the dictionary are stable tokens.
	for code, want := range map[int32]string{0: "SIPTO_above_RAN_ALLOWED", 1: "SIPTO_above_RAN_NOTALLOWED"} {
		item, err := Default.Enum(16777251, 1613, 10415, code)
		if err != nil {
			t.Fatal(err)
		}
		if item.Name != want {
			t.Errorf("SIPTO-Permission %d = %q, want %q", code, item.Name, want)
		}
	}
}
