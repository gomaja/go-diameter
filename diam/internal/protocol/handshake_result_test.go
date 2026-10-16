package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// A decoder can return either Go error-tree shape inside MessageError. Both
// the completion and later snapshots must own the evidence they expose.
func TestHandshakeJoinedErrorCopyIsolation(t *testing.T) {
	avp := diam.NewAVP(264, 64, 0, datatype.OctetString("original"))
	validation := &diam.ValidationError{FailedAVP: avp, ResultCode: diam.InvalidAVPValue}
	joined := errors.Join(fmt.Errorf("validation: %w", validation), errors.Join(base.ErrMissingOriginHost, strconv.ErrSyntax))
	c, result := rejectedDecoderHandshake(t, joined)
	wantMessage := result.Err().Error()
	avp.Data = datatype.OctetString("source changed")
	validation.ResultCode = 0
	joined.(interface{ Unwrap() []error }).Unwrap()[0] = errors.New("source child replaced")
	check := func(err error) {
		t.Helper()
		var got *diam.ValidationError
		if !errors.As(err, &got) || got.ResultCode != diam.InvalidAVPValue || string(got.FailedAVP.Data.(datatype.OctetString)) != "original" {
			t.Fatalf("joined validation evidence aliases source or accessor: %#v", got)
		}
		if !errors.Is(err, base.ErrMissingOriginHost) || !errors.Is(err, strconv.ErrSyntax) || err.Error() != wantMessage {
			t.Fatalf("joined error lost message or sentinel: %v", err)
		}
	}
	first := result.Err()
	check(first)
	var exposed *diam.ValidationError
	errors.As(first, &exposed)
	exposed.ResultCode = 0
	exposed.FailedAVP.Data = datatype.OctetString("accessor changed")
	outer := errors.Unwrap(first)
	outer.(interface{ Unwrap() []error }).Unwrap()[1] = nil
	check(result.Err())
	check(c.Snapshot().Handshake().Err())
}

func TestHandshakeTypedWrapperCopyIsolation(t *testing.T) {
	avp := diam.NewAVP(264, 64, 0, datatype.OctetString("original"))
	validation := &diam.ValidationError{FailedAVP: avp, ResultCode: diam.InvalidAVPValue}
	source := &strconv.NumError{Func: "ParseUint", Num: "123x", Err: errors.Join(validation, strconv.ErrSyntax)}
	c, result := rejectedDecoderHandshake(t, fmt.Errorf("decode: %w", source))
	source.Func, source.Num, source.Err = "mutated", "changed", nil
	avp.Data = datatype.OctetString("source changed")
	check := func(err error) *strconv.NumError {
		t.Helper()
		var got *strconv.NumError
		if !errors.As(err, &got) || got.Func != "ParseUint" || got.Num != "123x" || !errors.Is(got, strconv.ErrSyntax) {
			t.Fatalf("typed wrapper identity or fields lost: %#v (%v)", got, err)
		}
		var evidence *diam.ValidationError
		if !errors.As(got, &evidence) || string(evidence.FailedAVP.Data.(datatype.OctetString)) != "original" {
			t.Fatalf("typed wrapper evidence aliases source or accessor: %#v", evidence)
		}
		return got
	}
	first := check(result.Err())
	first.Func, first.Num = "accessor changed", "456x"
	var exposed *diam.ValidationError
	errors.As(first, &exposed)
	exposed.FailedAVP.Data = datatype.OctetString("accessor changed")
	first.Err = nil
	_ = check(result.Err())
	_ = check(c.Snapshot().Handshake().Err())
}

type handshakeTypedError struct {
	Err   error
	Notes []string
	Codes map[string][]int
	Count *int
	index int
}

func (e *handshakeTypedError) Error() string { return e.Notes[0] + ": " + e.Err.Error() }
func (e *handshakeTypedError) Unwrap() error { return e.Err }
func (e *handshakeTypedError) Is(target error) bool {
	return target == base.ErrNoCommonApplication && e.index == 7
}

func TestHandshakeTypedWrapperMutableMetadata(t *testing.T) {
	count := 3
	source := &handshakeTypedError{
		Err: strconv.ErrSyntax, Notes: []string{"original"}, Codes: map[string][]int{"original": {4}}, Count: &count, index: 7,
	}
	result := newHandshakeResult(source, nil)
	source.Notes[0], source.Codes["original"][0], *source.Count = "source changed", 9, 8
	check := func(err error) *handshakeTypedError {
		t.Helper()
		var got *handshakeTypedError
		if !errors.As(err, &got) {
			t.Fatalf("exported-field wrapper lost concrete type: %T", err)
		}
		if got.Notes[0] != "original" || got.Codes["original"][0] != 4 || *got.Count != 3 || !errors.Is(got, base.ErrNoCommonApplication) || !errors.Is(got, strconv.ErrSyntax) {
			t.Fatalf("wrapper lost metadata, Is method or sentinel: %#v", got)
		}
		return got
	}
	first := check(result.Err())
	first.Notes[0], first.Codes["original"][0], *first.Count, first.Err = "accessor changed", 0, 0, nil
	_ = check(result.Err())
}

func TestHandshakeTypedWrapperNil(t *testing.T) {
	for _, err := range []error{(*strconv.NumError)(nil), (*handshakeTypedError)(nil)} {
		if got := newHandshakeResult(err, nil).Err(); got != nil {
			t.Fatalf("typed nil wrapper became a non-nil cause: %#v", got)
		}
	}
}

type handshakeJoinedError struct {
	Message string
	Errors  []error
}

func (e *handshakeJoinedError) Error() string   { return e.Message }
func (e *handshakeJoinedError) Unwrap() []error { return e.Errors }

type handshakeValueError struct {
	Err      error
	Label    string
	Array    [2]string
	Metadata any
	NilSlice []string
	NilMap   map[string]string
	NilPtr   *string
}

func (e handshakeValueError) Error() string { return e.Label }
func (e handshakeValueError) Unwrap() error { return e.Err }

func TestHandshakeConcreteTreeShapes(t *testing.T) {
	source := &handshakeJoinedError{
		Message: "custom combined error",
		Errors: []error{handshakeValueError{
			Err: strconv.ErrRange, Label: "original", Array: [2]string{"a", "b"}, Metadata: []string{"metadata"},
		}, nil, strconv.ErrSyntax},
	}
	result := newHandshakeResult(source, nil)
	source.Message = "source changed"
	source.Errors[0].(handshakeValueError).Metadata.([]string)[0] = "source changed"
	source.Errors[0] = nil
	check := func(err error) *handshakeJoinedError {
		t.Helper()
		var joined *handshakeJoinedError
		if !errors.As(err, &joined) || joined.Message != "custom combined error" || len(joined.Errors) != 3 || joined.Errors[1] != nil {
			t.Fatalf("custom joined wrapper lost concrete type or metadata: %#v", joined)
		}
		var single handshakeValueError
		if !errors.As(err, &single) || single.Label != "original" || single.Array != [2]string{"a", "b"} || single.Metadata.([]string)[0] != "metadata" || single.NilSlice != nil || single.NilMap != nil || single.NilPtr != nil {
			t.Fatalf("value wrapper lost fields or isolated evidence: %#v", single)
		}
		if !errors.Is(err, strconv.ErrSyntax) || !errors.Is(err, strconv.ErrRange) {
			t.Fatal("custom error tree lost sentinel identity")
		}
		return joined
	}
	first := check(result.Err())
	first.Errors[0].(handshakeValueError).Metadata.([]string)[0] = "accessor changed"
	first.Errors[0] = nil
	_ = check(result.Err())
}

type handshakeJSONFailure struct{ cause error }

func (e handshakeJSONFailure) MarshalJSON() ([]byte, error) { return nil, e.cause }

type handshakeTextFailure struct{ cause error }

func (e handshakeTextFailure) MarshalText() ([]byte, error) { return nil, e.cause }

func TestHandshakeJSONWrapperCopyIsolation(t *testing.T) {
	for _, text := range []bool{false, true} {
		name := "MarshalJSON"
		if text {
			name = "MarshalText"
		}
		t.Run(name, func(t *testing.T) {
			avp := diam.NewAVP(264, 64, 0, datatype.OctetString("original"))
			cause := errors.Join(&diam.ValidationError{FailedAVP: avp, ResultCode: diam.InvalidAVPValue}, strconv.ErrSyntax)
			var value any = handshakeJSONFailure{cause}
			if text {
				value = handshakeTextFailure{cause}
			}
			_, source := json.Marshal(value)
			var original *json.MarshalerError
			if !errors.As(source, &original) {
				t.Fatalf("marshaler fixture did not return its typed error: %v", source)
			}
			_, result := rejectedDecoderHandshake(t, source)
			wantMessage, wantType := original.Error(), original.Type
			original.Type, original.Err = reflect.TypeFor[int](), nil
			avp.Data = datatype.OctetString("source changed")
			check := func(err error) *json.MarshalerError {
				t.Helper()
				var got *json.MarshalerError
				if !errors.As(err, &got) || got.Type != wantType || got.Error() != wantMessage || !errors.Is(got, strconv.ErrSyntax) {
					t.Fatalf("JSON wrapper lost concrete type, immutable Type, private method label or sentinel: %#v (%v)", got, err)
				}
				var evidence *diam.ValidationError
				if !errors.As(got, &evidence) || string(evidence.FailedAVP.Data.(datatype.OctetString)) != "original" {
					t.Fatal("JSON wrapper shares mutable cause evidence")
				}
				return got
			}
			first := check(result.Err())
			var evidence *diam.ValidationError
			errors.As(first, &evidence)
			evidence.FailedAVP.Data = datatype.OctetString("accessor changed")
			first.Type, first.Err = reflect.TypeFor[string](), nil
			_ = check(result.Err())
		})
	}
}

type mutableHandshakeType struct {
	reflect.Type
	Names []string
}

func TestHandshakeCustomReflectTypeMetadataIsolation(t *testing.T) {
	descriptor := mutableHandshakeType{Type: reflect.TypeFor[int](), Names: []string{"original"}}
	result := newHandshakeResult(&json.MarshalerError{Type: descriptor, Err: strconv.ErrSyntax}, nil)
	descriptor.Names[0] = "source changed"
	check := func() []string {
		t.Helper()
		var wrapper *json.MarshalerError
		if !errors.As(result.Err(), &wrapper) {
			t.Fatal("wrapper containing a custom Type lost concrete identity")
		}
		custom, ok := wrapper.Type.(mutableHandshakeType)
		if !ok || custom.Names[0] != "original" {
			t.Fatal("custom reflect.Type implementation retained mutable metadata")
		}
		return custom.Names
	}
	check()[0] = "accessor changed"
	check()
}

func rejectedDecoderHandshake(t *testing.T, cause error) (*Core, HandshakeResult) {
	t.Helper()
	c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
	sent := grant(t, c, c.Handle(event(Start)))
	c.Handle(complete(sent))
	m, err := base.BuildCEA(sent.Message, remote(t).Local, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	in := receive(m)
	in.Error = &diam.MessageError{ResultCode: diam.InvalidAVPValue, Err: cause}
	result := handshakeCompletion(t, c.Handle(in)).Handshake
	if result.Err() == nil || c.Snapshot().Phase() != Closed {
		t.Fatal("decoder rejection did not complete the production handshake")
	}
	return c, result
}
