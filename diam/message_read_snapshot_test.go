package diam

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

type dictionaryChangeBeforeBody struct {
	*bytes.Reader
	change func()
	reads  int
}

func (r *dictionaryChangeBeforeBody) Read(b []byte) (int, error) {
	if r.reads == 1 {
		r.change()
	}
	r.reads++
	return r.Reader.Read(b)
}

func TestReadMessageUsesSnapshotBeforeBodyRead(t *testing.T) {
	p, err := dict.New(dict.Base())
	if err != nil {
		t.Fatal(err)
	}
	m := NewRequest(DeviceWatchdog, 0, p)
	m.AddAVP(NewAVP(70001, 0, 0, datatype.UTF8String("value")))
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	r := &dictionaryChangeBeforeBody{Reader: bytes.NewReader(wire), change: func() {
		if err := p.Load(strings.NewReader(`<diameter><application id="0"><avp name="Body-Marker" code="70001"><data type="UTF8String"/></avp></application></diameter>`)); err != nil {
			t.Fatal(err)
		}
	}}
	decoded, err := ReadMessage(r, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.AVP) != 1 {
		t.Fatalf("AVPs = %d, want 1", len(decoded.AVP))
	}
	if _, ok := decoded.AVP[0].Data.(datatype.Unknown); !ok {
		t.Fatalf("body used a newer dictionary: decoded %T, want Unknown", decoded.AVP[0].Data)
	}
	if _, err := p.FindAVPByName(0, "Body-Marker"); err != nil {
		t.Fatalf("dictionary update did not run: %v", err)
	}
}
