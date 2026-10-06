package dict

import (
	"strings"
	"testing"
)

const strictXMLSample = `<?xml version="1.0"?>
<!-- dictionary -->
<diameter>
  <application id="0" name="Test">
    <vendor id="42" name="Supplier"/>
    <command code="123" name="Example" short="EX">
      <request proxiable="true"><rule avp="Example-AVP" required="true" max="1"/></request>
      <answer><rule avp="Example-AVP"/></answer>
    </command>
    <avp name="Example-AVP" code="123" must="M" may="P" must-not="V" may-encrypt="N" vendor-id="42">
      <data type="Enumerated"><item code="1" name="One"/></data>
    </avp>
    <avp name="Example-Group" code="124">
      <data type="Grouped"><rule avp="Example-AVP" fixed="true" min="1"/></data>
    </avp>
  </application>
</diameter>
<!-- trailing comment -->
`

func TestStrictDictionaryXML(t *testing.T) {
	tests := []struct {
		name, old, replacement string
	}{
		{"root attribute", `<diameter>`, `<diameter unexpected="1">`},
		{"application attribute", `name="Test"`, `name="Test" unknown="x"`},
		{"vendor attribute", `name="Supplier"`, `name="Supplier" unknowable="x"`},
		{"command attribute", `short="EX"`, `short="EX" unknowable="x"`},
		{"request attribute", `<request proxiable="true">`, `<request proxiable="true" unknown="x">`},
		{"answer attribute", `<answer>`, `<answer unknown="x">`},
		{"avp attribute", `must="M"`, `must="M" must_not="V"`},
		{"data attribute", `type="Enumerated"`, `type="Enumerated" unexpected="x"`},
		{"item attribute", `name="One"`, `name="One" unexpected="x"`},
		{"rule attribute in request", `max="1"`, `max="1" mmax="1"`},
		{"rule attribute in data", `fixed="true"`, `fixed="true" extra="x"`},
		{"root child", `<diameter>`, `<diameter><unknown/>`},
		{"application child", `<application id="0" name="Test">`, `<application id="0" name="Test"><unknown/>`},
		{"vendor child", `<vendor id="42" name="Supplier"/>`, `<vendor id="42" name="Supplier"><unknown/></vendor>`},
		{"command child", `<command code="123" name="Example" short="EX">`, `<command code="123" name="Example" short="EX"><unknown/>`},
		{"request child", `<request proxiable="true">`, `<request proxiable="true"><unknown/>`},
		{"answer child", `<answer>`, `<answer><unknown/>`},
		{"avp child", `<avp name="Example-Group" code="124">`, `<avp name="Example-Group" code="124"><unknown/>`},
		{"data child", `<data type="Enumerated">`, `<data type="Enumerated"><unknown/>`},
		{"item child", `<item code="1" name="One"/>`, `<item code="1" name="One"><unknown/></item>`},
		{"rule child", `<rule avp="Example-AVP" required="true" max="1"/>`, `<rule avp="Example-AVP" required="true" max="1"><unknown/></rule>`},
		{"wrong position known element", `<request proxiable="true">`, `<request proxiable="true"><item code="1" name="One"/>`},
		{"namespace root", `<diameter>`, `<x:diameter xmlns:x="urn:foreign">`},
		{"namespace child", `<vendor id="42"`, `<x:vendor xmlns:x="urn:foreign" id="42"`},
		{"namespace attribute", `name="Supplier"`, `name="Supplier" xmlns:x="urn:foreign" x:extra="x"`},
		{"default namespace", `<diameter>`, `<diameter xmlns="urn:foreign">`},
		{"duplicate attribute", `name="Supplier"`, `name="Supplier" name="Duplicate"`},
		{"text content", `<diameter>`, `<diameter>unmapped text`},
		{"second root", `<!-- trailing comment -->`, `<!-- trailing comment --><diameter/>`},
		{"trailing malformed element", `<!-- trailing comment -->`, `<!-- trailing comment --><unknown`},
	}
	if _, err := parseFile(strings.NewReader(strictXMLSample)); err != nil {
		t.Fatalf("valid dictionary: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(strictXMLSample, tc.old, tc.replacement, 1)
			if input == strictXMLSample {
				t.Fatal("test replacement did not apply")
			}
			if _, err := parseFile(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid dictionary")
			}
		})
	}
}

func TestStrictDictionaryXMLLoadIsAtomic(t *testing.T) {
	p := New()
	before := p.Snapshot()
	bad := strings.Replace(strictXMLSample, `max="1"`, `mmax="1"`, 1)
	if err := p.Load(strings.NewReader(bad)); err == nil {
		t.Fatal("accepted unknown rule attribute")
	}
	if p.Snapshot() != before {
		t.Fatal("failed load published a snapshot")
	}
}

func FuzzStrictDictionaryXML(f *testing.F) {
	f.Add([]byte(strictXMLSample))
	f.Add([]byte(strings.Replace(strictXMLSample, `max="1"`, `mmax="1"`, 1)))
	f.Add([]byte(`<diameter xmlns="urn:foreign"/>`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, err := parseFile(strings.NewReader(string(input)))
		if err == nil {
			withSecondRoot := append(append([]byte(nil), input...), []byte(`<diameter/>`)...)
			if _, err := parseFile(strings.NewReader(string(withSecondRoot))); err == nil {
				t.Fatal("accepted a second root after a valid dictionary")
			}
		}
	})
}
