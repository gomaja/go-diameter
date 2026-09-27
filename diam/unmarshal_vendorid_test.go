package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestUnmarshalVendorID(t *testing.T) {
	const dictXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter><application id="4">
<avp name="Example-Base" code="777" must="M" must-not="V"><data type="OctetString" /></avp>
<avp name="Example-Vendor" code="777" must="M,V" vendor-id="10415"><data type="Unsigned32" /></avp>
<avp name="Example-Group" code="778" must="M"><data type="Grouped">
<rule avp="Example-Base" required="false" max="2" />
<rule avp="Example-Vendor" required="false" max="2" />
</data></avp></application></diameter>`
	d, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(bytes.NewReader([]byte(dictXML))); err != nil {
		t.Fatal(err)
	}
	pairAVPs := func(prefix string, n uint32) []*AVP {
		return []*AVP{
			NewAVP(777, avp.Mbit, 0, datatype.OctetString(prefix+"-a")),
			NewAVP(777, avp.Mbit|avp.Vbit, 10415, datatype.Unsigned32(n)),
			NewAVP(777, avp.Mbit, 0, datatype.OctetString(prefix+"-b")),
			NewAVP(777, avp.Mbit|avp.Vbit, 10415, datatype.Unsigned32(n+1)),
		}
	}
	m := NewRequest(272, 4, d)
	for _, a := range pairAVPs("top", 10) {
		m.AddAVP(a)
	}
	m.AddAVP(NewAVP(778, avp.Mbit, 0, &GroupedAVP{AVP: pairAVPs("group", 20)}))
	type pair struct {
		Base   []datatype.OctetString `avp:"Example-Base"`
		Vendor []datatype.Unsigned32  `avp:"Example-Vendor"`
	}
	var dst struct {
		pair
		Group pair `avp:"Example-Group"`
	}
	if err := m.Unmarshal(&dst); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		got    pair
		prefix string
		n      uint32
	}{
		{"top", dst.pair, "top", 10}, {"group", dst.Group, "group", 20},
	} {
		if len(tc.got.Base) != 2 || len(tc.got.Vendor) != 2 {
			t.Fatalf("%s: lengths %d/%d", tc.name, len(tc.got.Base), len(tc.got.Vendor))
		}
		if string(tc.got.Base[0]) != tc.prefix+"-a" || string(tc.got.Base[1]) != tc.prefix+"-b" || uint32(tc.got.Vendor[0]) != tc.n || uint32(tc.got.Vendor[1]) != tc.n+1 {
			t.Errorf("%s: decoded %#v", tc.name, tc.got)
		}
	}
}
