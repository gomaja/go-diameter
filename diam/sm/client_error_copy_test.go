package sm

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// Decoder errors enter through the public MessageErrorHandler boundary. Dial
// must return detached error evidence with the same Is/As contract (§5.3.2).
func TestClientHandshakeErrorCopies(t *testing.T) {
	for _, joined := range []bool{false, true} {
		t.Run(map[bool]string{false: "typed-wrapper", true: "joined"}[joined], func(t *testing.T) {
			p := newClientCoreTCP(t, nil)
			var conn diam.Conn
			p.client.Handler.cores.Range(func(key, value any) bool { conn = key.(diam.Conn); return false })
			if conn == nil {
				t.Fatal("CER was sent without a connection core")
			}
			state := p.client.Handler.acceptedCore(conn, nil, false)
			failed := diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("synthetic.example"))
			validation := &diam.ValidationError{ResultCode: diam.InvalidAVPValue, FailedAVP: failed}
			number := &strconv.NumError{Func: "ParseUint", Num: "synthetic", Err: validation}
			var cause error = number
			if joined {
				cause = errors.Join(strconv.ErrSyntax, errors.Join(number, strconv.ErrRange))
			}
			messageErr := &diam.MessageError{ResultCode: diam.InvalidAVPLength, Err: cause}
			if err := p.client.Handler.HandleMessageError(conn, p.cer.Answer(diam.Success), messageErr); err != nil {
				t.Fatal(err)
			}
			result := p.dialResult(t)
			var copied *strconv.NumError
			if result.err == nil || !errors.As(result.err, &copied) {
				t.Fatalf("Dial error lost typed wrapper: %T %v", result.err, result.err)
			}
			if joined && (!errors.Is(result.err, strconv.ErrSyntax) || !errors.Is(result.err, strconv.ErrRange)) {
				t.Fatalf("Dial error lost joined branches: %v", result.err)
			}
			copied.Func = "mutated"
			var copiedValidation *diam.ValidationError
			if !errors.As(result.err, &copiedValidation) {
				t.Fatal("Dial error lost validation evidence")
			}
			copiedValidation.FailedAVP.Code = 0
			number.Num = "mutated original"
			failed.Code = 0
			stored := state.snapshot().Handshake().Err()
			var storedNumber *strconv.NumError
			var storedValidation *diam.ValidationError
			if !errors.As(stored, &storedNumber) || storedNumber.Func != "ParseUint" || storedNumber.Num != "synthetic" {
				t.Fatalf("core aliases typed error: %+v", storedNumber)
			}
			if !errors.As(stored, &storedValidation) || storedValidation.FailedAVP.Code != avp.OriginHost {
				t.Fatalf("core aliases joined evidence: %+v", storedValidation)
			}
		})
	}
}

func TestClientUnsignalledCoreLivesInConnectionContext(t *testing.T) {
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.RetransmitInterval = time.Hour
	c := newHandshakeConn()
	state := primeClientTestCore(t, cli, c)
	if cli.Handler.contextCore(c) != state {
		t.Fatal("dialed core not stored in Conn context")
	}
	cli.Handler.cores.Range(func(key, value any) bool {
		if key == c {
			t.Error("unsignalled dialed Conn retained by StateMachine")
		}
		return true
	})
}
