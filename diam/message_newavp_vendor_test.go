package diam

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestMessageAVPAPIsHaveTypedSignatures(t *testing.T) {
	type method struct {
		name string
		want reflect.Type
	}
	for _, tc := range []method{
		{"NewAVP", reflect.TypeOf(func(*Message, uint32, uint8, uint32, datatype.Type) (*AVP, error) { return nil, nil })},
		{"NewAVPByName", reflect.TypeOf(func(*Message, string, uint8, datatype.Type) (*AVP, error) { return nil, nil })},
		{"FindAVP", reflect.TypeOf(func(*Message, uint32, uint32) (*AVP, error) { return nil, nil })},
		{"FindAVPs", reflect.TypeOf(func(*Message, uint32, uint32) ([]*AVP, error) { return nil, nil })},
		{"FindAVPByName", reflect.TypeOf(func(*Message, string) (*AVP, error) { return nil, nil })},
		{"FindAVPsByName", reflect.TypeOf(func(*Message, string) ([]*AVP, error) { return nil, nil })},
		{"FindAVPsWithPath", reflect.TypeOf(func(*Message, ...AVPRef) []*AVP { return nil })},
	} {
		got, ok := reflect.TypeOf((*Message)(nil)).MethodByName(tc.name)
		if !ok || got.Type != tc.want {
			t.Errorf("%s has type %v, want %v", tc.name, got.Type, tc.want)
		}
	}
	codeField, ok := reflect.TypeOf(AVPRef{}).FieldByName("Code")
	if !ok || codeField.Type.Kind() != reflect.Uint32 {
		t.Errorf("AVPRef.Code has type %v, want uint32", codeField.Type)
	}
}

// RFC 6733 §4.1: name resolution supplies the definition's code and vendor.
func TestNewAVPByNameDerivesVendor(t *testing.T) {
	m := NewRequest(272, 4, dict.Default)
	method := reflect.ValueOf(m).MethodByName("NewAVPByName")
	if !method.IsValid() {
		t.Fatal("Message.NewAVPByName is absent")
	}
	wantType := reflect.TypeOf(func(string, uint8, datatype.Type) (*AVP, error) { return nil, nil })
	if method.Type() != wantType {
		t.Fatalf("Message.NewAVPByName has type %v, want %v", method.Type(), wantType)
	}
	add := func(name string) (*AVP, error) {
		results := method.Call([]reflect.Value{
			reflect.ValueOf(name),
			reflect.ValueOf(uint8(avp.Vbit)),
			reflect.ValueOf(datatype.UTF8String("00101")),
		})
		var a *AVP
		if !results[0].IsNil() {
			a = results[0].Interface().(*AVP)
		}
		var err error
		if !results[1].IsNil() {
			err = results[1].Interface().(error)
		}
		return a, err
	}
	length := m.Header.MessageLength
	if a, err := add("missing AVP"); a != nil || err == nil {
		t.Fatalf("unknown name = %v, %v", a, err)
	}
	if len(m.AVP) != 0 || m.Header.MessageLength != length {
		t.Fatal("rejected AVP changed message")
	}
	a, err := add("TGPP-GGSN-MCC-MNC")
	if err != nil || a == nil || a.Code != 9 || a.VendorID != 10415 || len(m.AVP) != 1 || m.AVP[0] != a {
		t.Fatalf("name-derived code/vendor = %v, %v", a, err)
	}
}

func TestMessageFindMissesDistinguishDictionaryFromMessage(t *testing.T) {
	m := NewRequest(272, 4, dict.Default)
	if got, err := m.FindAVP(9, 10415); got != nil || !errors.Is(err, ErrAVPNotFound) || errors.Is(err, dict.ErrNotFound) {
		t.Errorf("FindAVP miss = %v, %v", got, err)
	}
	if got, err := m.FindAVPs(9, 10415); got != nil || !errors.Is(err, ErrAVPNotFound) || errors.Is(err, dict.ErrNotFound) {
		t.Errorf("FindAVPs miss = %v, %v", got, err)
	}
	if got, err := m.FindAVPByName("TGPP-GGSN-MCC-MNC"); got != nil || !errors.Is(err, ErrAVPNotFound) || errors.Is(err, dict.ErrNotFound) {
		t.Errorf("FindAVPByName miss = %v, %v", got, err)
	}
	if got, err := m.FindAVPsByName("TGPP-GGSN-MCC-MNC"); got != nil || !errors.Is(err, ErrAVPNotFound) || errors.Is(err, dict.ErrNotFound) {
		t.Errorf("FindAVPsByName miss = %v, %v", got, err)
	}
	if got, err := m.FindAVPByName("undefined AVP"); got != nil || !errors.Is(err, dict.ErrNotFound) || errors.Is(err, ErrAVPNotFound) {
		t.Errorf("FindAVPByName definition miss = %v, %v", got, err)
	}
	if got, err := m.FindAVPsByName("undefined AVP"); got != nil || !errors.Is(err, dict.ErrNotFound) || errors.Is(err, ErrAVPNotFound) {
		t.Errorf("FindAVPsByName definition miss = %v, %v", got, err)
	}
}
