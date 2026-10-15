package protocol

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

var epoch = time.Unix(1000, 0)
var connection = Connection{Instance: 7, Generation: 1}

func configuration(t testing.TB) Config {
	t.Helper()
	d, err := dict.New(dict.Base())
	if err != nil {
		t.Fatal(err)
	}
	return Config{Connection: connection, Role: Responder, Dictionary: d,
		Local:            base.Settings{OriginHost: "local.example", OriginRealm: "example", VendorID: 1, ProductName: "test", HostIPAddresses: []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))}, AuthApplicationID: []*diam.AVP{diam.NewAVP(258, 64, 0, datatype.Unsigned32(4))}},
		HandshakeTimeout: 30 * time.Second, ClosingTimeout: 5 * time.Second}
}

func machine(t testing.TB, edit ...func(*Config)) *Core {
	t.Helper()
	cfg := configuration(t)
	for _, f := range edit {
		f(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func event(k InputKind) Input { return Input{Kind: k, Connection: connection, At: epoch} }
func kinds(es []Effect) []EffectKind {
	if len(es) == 0 {
		return nil
	}
	out := make([]EffectKind, len(es))
	for i, e := range es {
		out[i] = e.Kind
	}
	return out
}
func wantKinds(t testing.TB, es []Effect, want ...EffectKind) {
	t.Helper()
	if !reflect.DeepEqual(kinds(es), want) {
		t.Fatalf("effects=%v want=%v: %+v", kinds(es), want, es)
	}
}

// RFC 6733 §§5.6–5.6.1; #108 retirement: no event can revive a retired generation.
func TestRetirementIsPermanent(t *testing.T) {
	c := machine(t)
	wantKinds(t, c.Handle(event(Retire)))
	if c.Snapshot().Phase() != Retired {
		t.Fatal("retirement did not latch")
	}
	for k := Start; k <= Retire; k++ {
		in := event(k)
		in.Token = 99
		wantKinds(t, c.Handle(in))
		if c.Snapshot().Phase() != Retired {
			t.Fatalf("input %v revived generation", k)
		}
	}
}

// RFC 6733 §5.6.1: accepted admission expires independently of callbacks.
func TestAcceptedHandshakeDeadline(t *testing.T) {
	c := machine(t)
	es := c.Handle(event(Start))
	wantKinds(t, es, ArmTimer)
	if es[0].Timer != HandshakeTimer || !es[0].Deadline.Equal(epoch.Add(30*time.Second)) {
		t.Fatalf("timer=%+v", es[0])
	}
	in := event(TimerExpired)
	in.Timer = HandshakeTimer
	in.Token = es[0].Token
	in.At = es[0].Deadline
	wantKinds(t, c.Handle(in), StopTimer, Close, Notify)
	if c.Snapshot().Phase() != Closed {
		t.Fatal("handshake did not close")
	}
}
