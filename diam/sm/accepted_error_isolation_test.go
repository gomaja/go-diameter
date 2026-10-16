package sm

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func TestAcceptedDiagnosticErrorIsolationWire(t *testing.T) {
	p := newProtocolWire(t, nil, false)
	leaf := &json.SyntaxError{Offset: 7}
	m := diam.NewMessage(diam.DeviceWatchdog, 0, 0, 17, 18, p.conn.Dictionary())
	me := &diam.MessageError{ResultCode: diam.InvalidAVPValue, Err: errors.Join(errors.New("synthetic marker"), leaf)}
	if e := p.sm.HandleMessageError(p.conn, m, me); e != nil {
		t.Fatal(e)
	}
	e := protocolEvent(t, p.events)
	if e.Err.Kind() != diam.ProtocolHandshakeState || e.Err.ResultCode() != diam.InvalidAVPValue || !e.Closing {
		t.Fatalf("notification=%+v", e)
	}
	records := p.logs.Records()
	if len(records) != 1 {
		t.Fatalf("logs=%v", records)
	}
	cause, ok := logtest.Attr(records[0], "error").Any().(error)
	if !ok {
		t.Fatal("missing cause")
	}
	leaf.Offset = 99
	var got *json.SyntaxError
	if !errors.As(cause, &got) {
		t.Fatalf("typed error missing %T %v", cause, cause)
	}
	t.Logf("stored diagnostic SyntaxError.Offset=%d source=%d", got.Offset, leaf.Offset)
	if got.Offset != 7 {
		t.Fatal("accepted diagnostic aliased source error")
	}
	if !p.conn.Closed() {
		t.Fatal("pre-CER invalid message did not close")
	}
}
