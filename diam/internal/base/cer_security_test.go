package base_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func TestCERSecurityChecksEveryAVP(t *testing.T) {
	for _, tlsActive := range []bool{false, true} {
		for _, values := range [][]datatype.Type{
			nil, {datatype.Unsigned32(0)}, {datatype.Unsigned32(1)}, {datatype.Unsigned32(42)},
			{datatype.Unsigned32(1), datatype.Unsigned32(0)},
			{datatype.Unsigned32(0), datatype.Unknown{0, 1}},
			{datatype.Unknown{0, 1}, datatype.Unsigned32(0)},
		} {
			request, err := base.BuildCER(dict.Default, fixtureSettings())
			if err != nil {
				t.Fatal(err)
			}
			wantSecurity, malformed := len(values) != 0 && !tlsActive, false
			for _, v := range values {
				request.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, v))
				if n, ok := v.(datatype.Unsigned32); ok {
					if n == 0 {
						wantSecurity = false
					}
				} else {
					malformed = true
				}
			}
			failed, err := new(base.CER).ParseWithSecurity(request, base.Server, tlsActive)
			var messageErr *diam.MessageError
			switch {
			case malformed:
				if !errors.As(err, &messageErr) || messageErr.ResultCode != diam.InvalidAVPLength || failed != messageErr.FailedAVP {
					t.Fatalf("TLS %v values %v: failed=%v error=%v, want 5014", tlsActive, values, failed, err)
				}
			case wantSecurity:
				if !errors.Is(err, base.ErrNoCommonSecurity) {
					t.Fatalf("TLS %v values %v: error=%v, want no common security", tlsActive, values, err)
				}
			default:
				if err != nil {
					t.Fatalf("TLS %v values %v: %v", tlsActive, values, err)
				}
			}
		}
	}
}

func FuzzCERSecurityLength(f *testing.F) {
	for _, seed := range [][]byte{{}, {0, 1}, {0, 0, 0, 0}, {0, 0, 0, 1}, {1, 2, 3, 4, 5}} {
		f.Add(seed)
	}
	dictionary := dict.New(dict.Base)
	dictionary.SetStrict(false)
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 64 {
			return
		}
		request, err := base.BuildCER(dictionary, fixtureSettings())
		if err != nil {
			t.Fatal(err)
		}
		request.AddAVP(diam.NewAVP(avp.InbandSecurityID, avp.Mbit, 0, datatype.Unknown(payload)))
		wire, err := request.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
		if err != nil {
			t.Fatal(err)
		}
		failed, err := new(base.CER).ParseWithSecurity(decoded, base.Server, true)
		if len(payload) == 4 {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		var messageErr *diam.MessageError
		if !errors.As(err, &messageErr) || messageErr.ResultCode != diam.InvalidAVPLength || failed == nil {
			t.Fatalf("length %d: failed=%v error=%v, want 5014", len(payload), failed, err)
		}
	})
}
