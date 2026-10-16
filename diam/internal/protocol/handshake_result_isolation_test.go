package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type handshakeMetadataCycle struct {
	Err  error
	Self *handshakeMetadataCycle
}

func (*handshakeMetadataCycle) Error() string   { return "synthetic cyclic metadata" }
func (e *handshakeMetadataCycle) Unwrap() error { return e.Err }

type handshakeUnwrapCycle struct{ Err error }

func (*handshakeUnwrapCycle) Error() string   { return "synthetic cyclic unwrap" }
func (e *handshakeUnwrapCycle) Unwrap() error { return e.Err }

type handshakeJoinedCycle struct{ Errors []error }

func (*handshakeJoinedCycle) Error() string     { return "synthetic cyclic joined unwrap" }
func (e *handshakeJoinedCycle) Unwrap() []error { return e.Errors }

type handshakeMetadataContainer struct {
	Err      error
	Metadata any
}

func (*handshakeMetadataContainer) Error() string   { return "synthetic metadata" }
func (e *handshakeMetadataContainer) Unwrap() error { return e.Err }

type handshakeConcreteChain struct{ Err *handshakeConcreteChain }

func (*handshakeConcreteChain) Error() string { return "synthetic concrete chain" }
func (e *handshakeConcreteChain) Unwrap() error {
	if e.Err == nil {
		return nil
	}
	return e.Err
}

type handshakeAbsentError struct{}

func (*handshakeAbsentError) Error() string { return "absent" }

// Malformed decoder error graphs must terminate during capture, access and
// standard error traversal. A child process bounds the pre-fix stack overflow.
func TestHandshakeErrorCopyCycles(t *testing.T) {
	if shape := os.Getenv("DIAM_HANDSHAKE_ERROR_CYCLE"); shape != "" {
		debug.SetMaxStack(1 << 20)
		var source error
		var cea *base.CEA
		switch shape {
		case "metadata":
			e := &handshakeMetadataCycle{Err: strconv.ErrSyntax}
			e.Self, source = e, e
		case "metadata-map":
			metadata := map[string]any{}
			metadata["self"] = metadata
			source = &handshakeMetadataContainer{Err: strconv.ErrSyntax, Metadata: metadata}
		case "metadata-slice":
			metadata := make([]any, 1)
			metadata[0] = metadata
			source = &handshakeMetadataContainer{Err: strconv.ErrSyntax, Metadata: metadata}
		case "metadata-pointer":
			var metadata any
			metadata = &metadata
			source = &handshakeMetadataContainer{Err: strconv.ErrSyntax, Metadata: metadata}
		case "benign-dag", "deep-dag":
			depth := 2
			if shape == "deep-dag" {
				depth = 16
			}
			a := &diam.AVP{Code: 264, Data: datatype.OctetString("original")}
			for range depth {
				a = &diam.AVP{Code: 279, Data: &diam.GroupedAVP{AVP: []*diam.AVP{a, a}}}
			}
			source = &base.ErrUnexpectedAVP{AVP: a}
		case "single-unwrap":
			e := &handshakeUnwrapCycle{}
			e.Err, source = e, e
		case "joined-unwrap":
			e := &handshakeJoinedCycle{}
			e.Errors, source = []error{e, strconv.ErrSyntax}, e
		case "recursive-error-method":
			e := &strconv.NumError{Func: "synthetic", Num: "synthetic"}
			e.Err, source = e, e
		case "deep-chain":
			source = strconv.ErrSyntax
			for range 10000 {
				source = &strconv.NumError{Func: "synthetic", Num: "synthetic", Err: source}
			}
		case "deep-concrete-chain":
			var chain *handshakeConcreteChain
			for range 10000 {
				chain = &handshakeConcreteChain{Err: chain}
			}
			source = chain
		case "validation-avp":
			source = &diam.ValidationError{FailedAVP: handshakeCyclicAVP()}
		case "message-avp":
			source = &diam.MessageError{FailedAVP: handshakeCyclicAVP(), Err: strconv.ErrSyntax}
		case "unexpected-avp":
			source = &base.ErrUnexpectedAVP{AVP: handshakeCyclicAVP()}
		case "failed-result-cea", "handshake-cea":
			cea = &base.CEA{ResultCode: diam.UnableToComply, FailedAVP: []*diam.AVP{handshakeCyclicAVP()}}
			source = strconv.ErrSyntax
			if shape == "failed-result-cea" {
				source = &base.ErrFailedResultCode{CEA: cea}
			}
		default:
			t.Fatalf("unknown cycle shape %q", shape)
		}
		result := newHandshakeResult(source, cea)
		for range 2 {
			err := result.Err()
			if shape == "benign-dag" || shape == "deep-dag" {
				var unexpected *base.ErrUnexpectedAVP
				if !errors.As(err, &unexpected) {
					t.Fatal("shared graph lost its concrete parser error")
				}
				assertHandshakeAVPTree(t, unexpected.AVP)
				if shape == "benign-dag" {
					children := unexpected.AVP.Data.(*diam.GroupedAVP).AVP
					if _, ok := children[0].Data.(*diam.GroupedAVP); !ok {
						t.Fatal("first shared-group occurrence lost its evidence")
					}
					if _, ok := children[1].Data.(datatype.Unknown); !ok {
						t.Fatal("repeated shared-group occurrence was not bounded")
					}
				}
			}
			if err == nil || err.Error() == "" {
				t.Fatal("copy lost the decoder error")
			}
			var absent *handshakeAbsentError
			if errors.As(err, &absent) || errors.Is(err, strconv.ErrRange) {
				t.Fatal("copy invented a cause")
			}
			if (shape == "metadata" || shape == "metadata-map" || shape == "metadata-slice" || shape == "metadata-pointer" || shape == "joined-unwrap") && !errors.Is(err, strconv.ErrSyntax) {
				t.Fatal("cycle cut lost the independent sentinel branch")
			}
			var validation *diam.ValidationError
			if errors.As(err, &validation) {
				assertHandshakeAVPFinite(t, validation.FailedAVP)
			}
			var malformed *diam.MessageError
			if errors.As(err, &malformed) {
				assertHandshakeAVPFinite(t, malformed.FailedAVP)
			}
			var unexpected *base.ErrUnexpectedAVP
			if errors.As(err, &unexpected) {
				assertHandshakeAVPFinite(t, unexpected.AVP)
			}
			var failed *base.ErrFailedResultCode
			if errors.As(err, &failed) {
				assertHandshakeAVPFinite(t, failed.FailedAVP[0])
			}
			if copied := result.CEA(); copied != nil {
				assertHandshakeAVPFinite(t, copied.FailedAVP[0])
			}
		}
		return
	}
	for _, shape := range []string{"metadata", "metadata-map", "metadata-slice", "metadata-pointer", "benign-dag", "deep-dag", "single-unwrap", "joined-unwrap", "recursive-error-method", "deep-chain", "deep-concrete-chain", "validation-avp", "message-avp", "unexpected-avp", "failed-result-cea", "handshake-cea"} {
		t.Run(shape, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestHandshakeErrorCopyCycles$", "-test.count=1")
			cmd.Env = append(os.Environ(), "DIAM_HANDSHAKE_ERROR_CYCLE="+shape)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("error graph did not terminate safely: %v\n%s", err, out)
			}
		})
	}
}

func assertHandshakeAVPTree(t *testing.T, root *diam.AVP) {
	t.Helper()
	seen := make(map[*diam.GroupedAVP]bool)
	queue := []*diam.AVP{root}
	count := 0
	for len(queue) != 0 {
		a := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		count++
		if count > 128 {
			t.Fatal("shared graph expanded beyond its source graph")
		}
		if grouped, ok := a.Data.(*diam.GroupedAVP); ok && grouped != nil {
			if seen[grouped] {
				t.Fatal("copied shared graph would expand during rendering")
			}
			seen[grouped] = true
			queue = append(queue, grouped.AVP...)
		}
	}
	if _, err := root.Serialize(); err != nil {
		t.Fatal(err)
	}
}

func handshakeCyclicAVP() *diam.AVP {
	a := &diam.AVP{Code: 279}
	a.Data = &diam.GroupedAVP{AVP: []*diam.AVP{a}}
	return a
}

func assertHandshakeAVPFinite(t *testing.T, a *diam.AVP) {
	t.Helper()
	if a == nil || a.Code != 279 {
		t.Fatal("cyclic AVP lost its outer evidence")
	}
	if _, err := a.Serialize(); err != nil {
		t.Fatalf("copied AVP is not finite serializable evidence: %v", err)
	}
}

type handshakeMutableLeaf struct {
	Message  string
	Metadata map[string][]int
}

type handshakeStatelessSentinel struct{}

func (*handshakeStatelessSentinel) Error() string { return "synthetic stateless sentinel" }

func (e *handshakeMutableLeaf) Error() string { return e.Message }

func TestHandshakeAdditionalMutableLeaves(t *testing.T) {
	t.Run("JSON-type", func(t *testing.T) {
		source := &json.UnmarshalTypeError{Value: "number", Type: reflect.TypeFor[string](), Offset: 7, Struct: "synthetic", Field: "field"}
		result := newHandshakeResult(source, nil)
		source.Value, source.Offset = "source changed", 100
		for range 2 {
			var got *json.UnmarshalTypeError
			if !errors.As(result.Err(), &got) || got.Value != "number" || got.Offset != 7 || got.Type != reflect.TypeFor[string]() || got.Struct != "synthetic" || got.Field != "field" {
				t.Fatalf("JSON type error lost concrete type or fields: %#v", got)
			}
			got.Value, got.Offset, got.Type = "accessor changed", 200, nil
		}
	})
	t.Run("custom-leaf", func(t *testing.T) {
		source := &handshakeMutableLeaf{Message: "synthetic", Metadata: map[string][]int{"synthetic": {7}}}
		result := newHandshakeResult(source, nil)
		source.Message, source.Metadata["synthetic"][0] = "source changed", 100
		for range 2 {
			var got *handshakeMutableLeaf
			if !errors.As(result.Err(), &got) || got.Message != "synthetic" || got.Metadata["synthetic"][0] != 7 {
				t.Fatalf("custom leaf shares exported fields: %#v", got)
			}
			got.Message, got.Metadata["synthetic"][0] = "accessor changed", 200
		}
	})
	for _, sentinel := range []error{errors.New("synthetic sentinel"), io.EOF, strconv.ErrSyntax, context.Canceled, &handshakeStatelessSentinel{}} {
		if got := newHandshakeResult(sentinel, nil).Err(); got != sentinel {
			t.Errorf("immutable sentinel identity changed: %T %v", sentinel, sentinel)
		}
	}
}

func TestHandshakeMutableLeafCopyIsolation(t *testing.T) {
	source := &json.SyntaxError{Offset: 7}
	result := newHandshakeResult(errors.Join(source, strconv.ErrSyntax), nil)
	source.Offset = 100
	for range 2 {
		err := result.Err()
		var syntax *json.SyntaxError
		if !errors.As(err, &syntax) {
			t.Fatal("mutable leaf lost its concrete type")
		}
		if syntax.Offset != 7 {
			t.Fatalf("mutable leaf aliases its source or accessor: Offset=%d, want 7", syntax.Offset)
		}
		if !errors.Is(err, strconv.ErrSyntax) {
			t.Fatal("immutable sentinel identity changed")
		}
		syntax.Offset = 200
	}
}

func TestHandshakeKnownCEAValueAndFields(t *testing.T) {
	a := diam.NewAVP(264, 64, 0, datatype.OctetString("original"))
	cea := &base.CEA{
		OriginHost: "synthetic.example", OriginRealm: "example", ResultCode: diam.UnableToComply,
		OriginStateID: 7, VendorID: 8, ProductName: "synthetic", ErrorMessage: "synthetic rejection",
		HostIPAddresses:   []datatype.Address{{Family: datatype.AddressFamilyIPv4, Value: []byte{127, 0, 0, 1}}},
		SupportedVendorID: []*diam.AVP{a}, FailedAVP: []*diam.AVP{a}, AcctApplicationID: []*diam.AVP{a},
		AuthApplicationID: []*diam.AVP{a}, VendorSpecificApplicationID: []*diam.AVP{a},
	}
	result := newHandshakeResult(base.ErrFailedResultCode{CEA: cea}, cea)
	a.Code, a.Data, cea.HostIPAddresses[0].Value[0], cea.ProductName = 0, datatype.OctetString("source changed"), 1, "source changed"
	for range 2 {
		var typed base.ErrFailedResultCode
		if !errors.As(result.Err(), &typed) || typed.CEA == nil {
			t.Fatal("value parser error lost its concrete type or parsed CEA")
		}
		for _, copied := range []*base.CEA{typed.CEA, result.CEA()} {
			if copied.OriginHost != "synthetic.example" || copied.OriginRealm != "example" || copied.ResultCode != diam.UnableToComply || copied.OriginStateID != 7 || copied.VendorID != 8 || copied.ProductName != "synthetic" || copied.ErrorMessage != "synthetic rejection" || copied.HostIPAddresses[0].Value[0] != 127 {
				t.Fatalf("known CEA scalar/address evidence changed: %#v", copied)
			}
			for _, avps := range [][]*diam.AVP{copied.SupportedVendorID, copied.FailedAVP, copied.AcctApplicationID, copied.AuthApplicationID, copied.VendorSpecificApplicationID} {
				if len(avps) != 1 || avps[0].Code != 264 || string(avps[0].Data.(datatype.OctetString)) != "original" {
					t.Fatal("known CEA list aliases mutable evidence")
				}
				avps[0].Code, avps[0].Data = 0, datatype.OctetString("accessor changed")
			}
			copied.ProductName, copied.HostIPAddresses[0].Value[0] = "accessor changed", 2
		}
	}
}

func TestHandshakeWideRejectedCEA(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "scalar", true: "grouped"}[grouped], func(t *testing.T) {
			c := machine(t, func(cfg *Config) { cfg.Role = Initiator })
			sent := grant(t, c, c.Handle(event(Start)))
			c.Handle(complete(sent))
			m, err := base.BuildCEA(sent.Message, remote(t).Local, diam.NoCommonApplication)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 5000 {
				if grouped {
					m.AddAVP(diam.NewAVP(260, 64, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
						diam.NewAVP(266, 64, 0, datatype.Unsigned32(i+1)),
						diam.NewAVP(258, 64, 0, datatype.Unsigned32(4)),
					}}))
				} else {
					m.AddAVP(diam.NewAVP(265, 64, 0, datatype.Unsigned32(i+1)))
				}
			}
			result := handshakeCompletion(t, c.Handle(receive(m))).Handshake
			var failed *base.ErrFailedResultCode
			if !errors.As(result.Err(), &failed) {
				t.Fatalf("core lost rejected CEA concrete error: %v", result.Err())
			}
			for _, cea := range []*base.CEA{failed.CEA, result.CEA(), c.Snapshot().Handshake().CEA()} {
				avps := cea.SupportedVendorID
				if grouped {
					avps = cea.VendorSpecificApplicationID
				}
				if len(avps) != 5000 {
					t.Fatalf("core CEA evidence truncated: %d AVPs, want 5000", len(avps))
				}
				for i, a := range avps {
					if grouped {
						g, ok := a.Data.(*diam.GroupedAVP)
						if !ok || len(g.AVP) != 2 {
							t.Fatalf("core grouped CEA evidence truncated at %d: %T", i, a.Data)
						}
						a = g.AVP[0]
					}
					if id, ok := a.Data.(datatype.Unsigned32); !ok || uint32(id) != uint32(i+1) {
						t.Fatalf("core CEA value truncated at %d: %T %v", i, a.Data, a.Data)
					}
					a.Data = datatype.Unsigned32(0)
				}
			}
		})
	}
}

func TestHandshakeKnownEvidenceDepth(t *testing.T) {
	for _, depth := range []int{31, 32, 80} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) {
			a := diam.NewAVP(264, 64, 0, datatype.OctetString("original"))
			for range depth {
				a = &diam.AVP{Code: 279, Flags: 64, Data: &diam.GroupedAVP{AVP: []*diam.AVP{a}}}
			}
			want, err := a.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			cfg := configuration(t)
			if depth > cfg.Dictionary.MaxGroupedDepth() {
				cfg.Dictionary.SetMaxGroupedDepth(depth + 1)
			}
			cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 1, 2, cfg.Dictionary)
			message, err := base.BuildCEA(cer, cfg.Local, diam.NoCommonApplication)
			if err != nil {
				t.Fatal(err)
			}
			message.AddAVP(a)
			raw, err := message.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := diam.ReadMessage(bytes.NewReader(raw), cfg.Dictionary)
			if err != nil {
				t.Fatal(err)
			}
			if err := base.ValidateMessage(decoded); err != nil {
				t.Fatalf("depth fixture is not valid decoded CEA evidence: %v", err)
			}
			var parsed base.CEA
			parseErr := parsed.Parse(decoded, base.ParseOptions{Role: base.Client, Dictionary: cfg.Dictionary})
			var failed *base.ErrFailedResultCode
			if !errors.As(parseErr, &failed) {
				t.Fatalf("depth fixture did not produce a parsed failed CEA: %v", parseErr)
			}
			result := newHandshakeResult(parseErr, &parsed)
			if !errors.As(result.Err(), &failed) {
				t.Fatal("known parser evidence lost its concrete error type")
			}
			for _, cea := range []*base.CEA{failed.CEA, result.CEA()} {
				got, err := cea.FailedAVP[0].Serialize()
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("finite known depth %d truncated: %d bytes, want %d (%v)", depth, len(got), len(want), err)
				}
				cea.FailedAVP[0].Data = datatype.Unknown(nil)
			}
		})
	}
}

func TestHandshakeKnownEvidenceThroughMetadata(t *testing.T) {
	cea := &base.CEA{ResultCode: diam.UnableToComply}
	for i := range 5000 {
		cea.SupportedVendorID = append(cea.SupportedVendorID, diam.NewAVP(265, 64, 0, datatype.Unsigned32(i+1)))
	}
	a := &diam.AVP{Code: 279}
	a.Data = &diam.GroupedAVP{AVP: []*diam.AVP{a}}
	result := newHandshakeResult(&handshakeMetadataContainer{Err: strconv.ErrSyntax, Metadata: []any{cea, a}}, nil)
	var copied *handshakeMetadataContainer
	if !errors.As(result.Err(), &copied) || !errors.Is(result.Err(), strconv.ErrSyntax) {
		t.Fatal("typed metadata wrapper lost its concrete type or sentinel")
	}
	metadata := copied.Metadata.([]any)
	if got := metadata[0].(*base.CEA); len(got.SupportedVendorID) != 5000 || got.SupportedVendorID[4999].Data.(datatype.Unsigned32) != 5000 {
		t.Fatal("known CEA in exported metadata was truncated")
	}
	assertHandshakeAVPFinite(t, metadata[1].(*diam.AVP))
}

type handshakePrivateScalarLeaf struct{ offset int }

func (*handshakePrivateScalarLeaf) Error() string     { return "synthetic mutable scalar leaf" }
func (e *handshakePrivateScalarLeaf) Offset() int     { return e.offset }
func (e *handshakePrivateScalarLeaf) SetOffset(n int) { e.offset = n }

func TestHandshakePrivateScalarLeafIsolation(t *testing.T) {
	original := &handshakePrivateScalarLeaf{offset: 7}
	c, result := rejectedDecoderHandshake(t, errors.Join(original, strconv.ErrSyntax))
	var exposed *handshakePrivateScalarLeaf
	if !errors.As(result.Err(), &exposed) || exposed.Offset() != 7 {
		t.Fatal("private scalar leaf lost its concrete type or state")
	}
	exposed.SetOffset(100)
	var stored *handshakePrivateScalarLeaf
	if !errors.As(c.Snapshot().Handshake().Err(), &stored) {
		t.Fatal("core lost the private scalar leaf type")
	}
	if stored.Offset() != 7 {
		t.Fatalf("returned private scalar leaf changes core evidence: Offset=%d, want 7", stored.Offset())
	}
	original.SetOffset(200)
	if !errors.As(result.Err(), &stored) {
		t.Fatal("captured error lost the private scalar leaf type")
	}
	if stored.Offset() != 7 {
		t.Fatalf("source private scalar leaf changes captured evidence: Offset=%d, want 7", stored.Offset())
	}
}
