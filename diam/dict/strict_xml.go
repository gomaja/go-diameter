package dict

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// strictDictionaryXML validates the complete token stream before the XML
// decoder assigns fields. In particular, the Rule custom unmarshaler sees
// tokens from this same reader, so its nested content is checked too.
type strictDictionaryXML struct {
	source   *xml.Decoder
	stack    []string
	complete bool
}

type dictionaryElement struct {
	children map[string]bool
	attrs    map[string]bool
}

func names(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, value := range values {
		m[value] = true
	}
	return m
}

// dictionaryElements lists, for each element, the children and attributes
// that the XML fields in skel.go decode; TestStrictDictionarySchemaMatchesSkel
// keeps the two aligned. A child is valid only under the listed parent; the
// same applies to every attribute.
var dictionaryElements = map[string]dictionaryElement{
	"diameter":    {children: names("application")},
	"application": {children: names("vendor", "command", "avp"), attrs: names("id", "type", "name")},
	"vendor":      {attrs: names("id", "name")},
	"command":     {children: names("request", "answer"), attrs: names("code", "name", "short")},
	"request":     {children: names("rule"), attrs: names("proxiable")},
	"answer":      {children: names("rule"), attrs: names("proxiable")},
	"avp":         {children: names("data"), attrs: names("name", "code", "must", "may", "must-not", "may-encrypt", "vendor-id")},
	"data":        {children: names("item", "rule"), attrs: names("type")},
	"item":        {attrs: names("code", "name")},
	"rule":        {attrs: names("avp", "required", "min", "max", "fixed", "must-not")},
}

func (v *strictDictionaryXML) Token() (xml.Token, error) {
	tok, err := v.source.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case xml.StartElement:
		if t.Name.Space != "" {
			return nil, fmt.Errorf("dictionary XML: namespaced element %q", xmlName(t.Name))
		}
		if len(v.stack) == 0 {
			if v.complete || t.Name.Local != "diameter" {
				return nil, fmt.Errorf("dictionary XML: unexpected root element <%s>", t.Name.Local)
			}
		} else {
			parent := v.stack[len(v.stack)-1]
			if !dictionaryElements[parent].children[t.Name.Local] {
				return nil, fmt.Errorf("dictionary XML: unexpected <%s> in <%s>", t.Name.Local, parent)
			}
		}
		allowed := dictionaryElements[t.Name.Local].attrs
		seen := make(map[string]bool, len(t.Attr))
		for _, attr := range t.Attr {
			if attr.Name.Space != "" || !allowed[attr.Name.Local] {
				return nil, fmt.Errorf("dictionary XML: unexpected attribute %q on <%s>", xmlName(attr.Name), t.Name.Local)
			}
			if seen[attr.Name.Local] {
				return nil, fmt.Errorf("dictionary XML: duplicate attribute %q on <%s>", attr.Name.Local, t.Name.Local)
			}
			seen[attr.Name.Local] = true
		}
		v.stack = append(v.stack, t.Name.Local)
	case xml.EndElement:
		if len(v.stack) == 0 || v.stack[len(v.stack)-1] != t.Name.Local || t.Name.Space != "" {
			return nil, fmt.Errorf("dictionary XML: unexpected closing element </%s>", t.Name.Local)
		}
		v.stack = v.stack[:len(v.stack)-1]
		if len(v.stack) == 0 {
			v.complete = true
		}
	case xml.CharData:
		if len(strings.TrimSpace(string(t))) != 0 {
			return nil, fmt.Errorf("dictionary XML: unexpected text content")
		}
	case xml.Directive:
		return nil, fmt.Errorf("dictionary XML: directives are unsupported")
	case xml.ProcInst:
		// The XML declaration is the only processing instruction used by the
		// bundled dictionaries. The underlying decoder checks its syntax.
		if !strings.EqualFold(t.Target, "xml") {
			return nil, fmt.Errorf("dictionary XML: unexpected processing instruction %q", t.Target)
		}
	case xml.Comment:
		// Comments are allowed between all dictionary elements.
	default:
		return nil, fmt.Errorf("dictionary XML: unexpected token %T", tok)
	}
	return tok, nil
}

// xmlName renders n as written in the document, with its namespace prefix
// only when it has one.
func xmlName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

var _ xml.TokenReader = (*strictDictionaryXML)(nil)
