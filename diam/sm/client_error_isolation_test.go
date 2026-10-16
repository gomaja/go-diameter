package sm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

type clientHandshakeMetadataCycle struct {
	Err  error
	Self *clientHandshakeMetadataCycle
}

func (*clientHandshakeMetadataCycle) Error() string   { return "synthetic cyclic decoder metadata" }
func (e *clientHandshakeMetadataCycle) Unwrap() error { return e.Err }

func TestClientHandshakeCyclicErrorMetadata(t *testing.T) {
	if shape := os.Getenv("DIAM_CLIENT_ERROR_CYCLE"); shape != "" {
		debug.SetMaxStack(1 << 20)
		p := newClientCoreTCP(t, nil)
		var conn diam.Conn
		p.client.Handler.cores.Range(func(key, _ any) bool { conn = key.(diam.Conn); return false })
		if conn == nil {
			t.Fatal("CER was sent without a connection core")
		}
		state := p.client.Handler.acceptedCore(conn, nil, false)
		metadata := &clientHandshakeMetadataCycle{Err: strconv.ErrSyntax}
		metadata.Self = metadata
		var cause error = metadata
		if shape == "failed-avp" {
			a := &diam.AVP{Code: 279}
			a.Data = &diam.GroupedAVP{AVP: []*diam.AVP{a}}
			cause = errors.Join(&diam.ValidationError{FailedAVP: a}, strconv.ErrSyntax)
		}
		if err := p.client.Handler.HandleMessageError(conn, p.cer.Answer(diam.Success), &diam.MessageError{ResultCode: diam.InvalidAVPLength, Err: cause}); err != nil {
			t.Fatal(err)
		}
		result := p.dialResult(t)
		for _, err := range []error{result.err, state.snapshot().Handshake().Err()} {
			if err == nil || err.Error() == "" || !errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
				t.Fatal("cyclic metadata lost the independent decoder cause")
			}
			if shape == "failed-avp" {
				var validation *diam.ValidationError
				if !errors.As(err, &validation) || validation.FailedAVP == nil || validation.FailedAVP.Code != 279 {
					t.Fatal("cyclic Failed-AVP lost concrete validation evidence")
				}
				if _, err := validation.FailedAVP.Serialize(); err != nil {
					t.Fatalf("copied Failed-AVP is not finite: %v", err)
				}
			}
		}
		return
	}
	for _, shape := range []string{"metadata", "failed-avp"} {
		t.Run(shape, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestClientHandshakeCyclicErrorMetadata$", "-test.count=1")
			cmd.Env = append(os.Environ(), "DIAM_CLIENT_ERROR_CYCLE="+shape)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("public Client error path did not terminate safely: %v\n%s", err, out)
			}
		})
	}
}

func TestClientHandshakeJoinedMutableLeafIsolation(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "typed-wrapper"}[wrapped], func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			var conn diam.Conn
			p.client.Handler.cores.Range(func(key, _ any) bool { conn = key.(diam.Conn); return false })
			if conn == nil {
				t.Fatal("CER was sent without a connection core")
			}
			state := p.client.Handler.acceptedCore(conn, nil, false)
			var syntax *json.SyntaxError
			if err := json.Unmarshal([]byte("!"), new(any)); !errors.As(err, &syntax) {
				t.Fatalf("fixture did not create a JSON syntax error: %v", err)
			}
			syntax.Offset = 7
			cause := errors.Join(syntax, strconv.ErrSyntax)
			if wrapped {
				cause = &strconv.NumError{Func: "synthetic", Num: "synthetic", Err: cause}
			}
			if err := p.client.Handler.HandleMessageError(conn, p.cer.Answer(diam.Success), &diam.MessageError{ResultCode: diam.InvalidAVPLength, Err: cause}); err != nil {
				t.Fatal(err)
			}
			result := p.dialResult(t)
			var exposed *json.SyntaxError
			if !errors.As(result.err, &exposed) || exposed.Offset != 7 || exposed.Error() != syntax.Error() {
				t.Fatalf("Dial lost JSON syntax error fields or concrete type: %v", result.err)
			}
			exposed.Offset = 100
			var stored *json.SyntaxError
			if !errors.As(state.snapshot().Handshake().Err(), &stored) {
				t.Fatal("core lost the JSON syntax error type")
			}
			if stored.Offset != 7 {
				t.Fatalf("Dial's mutable leaf changes core evidence: Offset=%d, want 7", stored.Offset)
			}
			syntax.Offset, stored.Offset = 200, 300
			fresh := state.snapshot().Handshake().Err()
			if !errors.As(fresh, &stored) || !errors.Is(fresh, strconv.ErrSyntax) {
				t.Fatal("fresh snapshot lost concrete type or sentinel identity")
			}
			if stored.Offset != 7 {
				t.Fatalf("source or snapshot mutable leaf changes core evidence: Offset=%d, want 7", stored.Offset)
			}
		})
	}
}

// A failed CEA retains its complete parsed evidence even when its legal
// repeatable AVPs exceed the generic error-metadata traversal budget.
func TestClientHandshakeWideRejectedCEA(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "scalar", true: "grouped"}[grouped], func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			cea := protocolClientCEA(p.cer, diam.NoCommonApplication)
			for i := range 5000 {
				code := uint32(i + 1)
				if grouped {
					cea.AddAVP(diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
						diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(code)),
						diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
					}}))
				} else {
					cea.AddAVP(diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(code)))
				}
			}
			p.send(t, cea)
			result := p.dialResult(t)
			var failed *smparser.ErrFailedResultCode
			if !errors.As(result.err, &failed) || failed.ResultCode != diam.NoCommonApplication {
				t.Fatalf("Dial lost parsed rejected CEA: %T %v", result.err, result.err)
			}
			avps := failed.SupportedVendorID
			if grouped {
				avps = failed.VendorSpecificApplicationID
			}
			if len(avps) != 5000 {
				t.Fatalf("parsed CEA evidence truncated: %d AVPs, want 5000", len(avps))
			}
			for i, a := range avps {
				if grouped {
					g, ok := a.Data.(*diam.GroupedAVP)
					if !ok || len(g.AVP) != 2 {
						t.Fatalf("parsed grouped CEA evidence truncated at %d: %T", i, a.Data)
					}
					a = g.AVP[0]
				}
				if id, ok := a.Data.(datatype.Unsigned32); !ok || uint32(id) != uint32(i+1) {
					t.Fatalf("parsed CEA value truncated at %d: %T %v", i, a.Data, a.Data)
				}
			}
		})
	}
}

type clientPrivateScalarLeaf struct{ offset int }

func (*clientPrivateScalarLeaf) Error() string     { return "synthetic mutable decoder leaf" }
func (e *clientPrivateScalarLeaf) Offset() int     { return e.offset }
func (e *clientPrivateScalarLeaf) SetOffset(n int) { e.offset = n }

func TestClientHandshakeJoinedPrivateScalarLeafIsolation(t *testing.T) {
	p := newClientCoreTCP(t, nil)
	var conn diam.Conn
	p.client.Handler.cores.Range(func(key, _ any) bool { conn = key.(diam.Conn); return false })
	if conn == nil {
		t.Fatal("CER was sent without a connection core")
	}
	state := p.client.Handler.acceptedCore(conn, nil, false)
	original := &clientPrivateScalarLeaf{offset: 7}
	cause := errors.Join(original, strconv.ErrSyntax)
	if err := p.client.Handler.HandleMessageError(conn, p.cer.Answer(diam.Success), &diam.MessageError{ResultCode: diam.InvalidAVPLength, Err: cause}); err != nil {
		t.Fatal(err)
	}
	result := p.dialResult(t)
	var exposed *clientPrivateScalarLeaf
	if !errors.As(result.err, &exposed) || exposed.Offset() != 7 {
		t.Fatal("Dial lost private scalar leaf type or state")
	}
	exposed.SetOffset(100)
	var stored *clientPrivateScalarLeaf
	if !errors.As(state.snapshot().Handshake().Err(), &stored) {
		t.Fatal("core lost the private scalar decoder leaf type")
	}
	if stored.Offset() != 7 {
		t.Fatalf("Dial's private scalar leaf changes core evidence: Offset=%d, want 7", stored.Offset())
	}
	original.SetOffset(200)
	fresh := state.snapshot().Handshake().Err()
	if !errors.As(fresh, &stored) || !errors.Is(fresh, strconv.ErrSyntax) {
		t.Fatal("fresh snapshot lost private scalar leaf type or sentinel")
	}
	if stored.Offset() != 7 {
		t.Fatalf("source private scalar leaf changes core evidence: Offset=%d, want 7", stored.Offset())
	}
}
