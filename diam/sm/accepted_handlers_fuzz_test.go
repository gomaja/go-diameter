package sm

import (
	"bytes"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/protocol"
)

// FuzzAcceptedHandlerAccounting varies committed requests and answers, their
// completion order, panics, abandoned batches and route removal. RFC 6733 §5.4: each wire DPA
// reflects the request handlers still owed at its admission point.
func FuzzAcceptedHandlerAccounting(f *testing.F) {
	for _, seed := range [][]byte{{}, {1}, {0}, {3}, {5}, {7}, {9}, {11}, {1, 0, 5, 9, 3}, {1, 1, 1, 1}, {17}, {33}, {49}, {51}, {1, 49, 0, 7}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 8 {
			operations = operations[:8]
		}
		c := &acceptedAdapterNotifyConn{handshakeConn: newHandshakeConn(), closed: make(chan struct{})}
		replaceAdmission(c, "CEA")
		cfg := testMessageErrorSettings(c.Dictionary())
		cfg.AcctApplicationID = []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}
		cfg.DPRCloseTimeout = time.Hour
		cfg.OnDWR = func(diam.Conn, *diam.Message) { panic("synthetic pre-admit panic") }
		sm := mustNewStateMachine(t, cfg)
		for _, request := range []bool{false, true} {
			sm.HandleIdx(diam.CommandIndex{AppID: 1001, Code: 0xeeff, Request: request}, diam.HandlerFunc(func(_ diam.Conn, m *diam.Message) {
				if m.Header.EndToEndID&4 != 0 {
					panic("synthetic handler panic")
				}
			}))
		}
		first := diam.NewMessage(0xeeff, diam.RequestFlag, 1001, 1, 0, c.Dictionary())
		state := sm.acceptedCore(c, first, true)
		if state == nil {
			t.Fatal("external admission did not create a core")
		}
		defer func() { state.apply(protocol.Input{Kind: protocol.Abort}); c.Close() }()
		type committed struct {
			batch acceptedBatch
			flags byte
		}
		var pending []committed
		remaining := 0
		run := func(item committed) {
			t.Helper()
			mux := sm.mux
			if item.flags&8 != 0 {
				sm.mux = diam.NewServeMux()
			}
			batch := item.batch
			if item.flags&32 != 0 {
				batch = acceptedBatch{following: []acceptedBatch{batch}}
			}
			if item.flags&16 != 0 {
				batch.effects = append([]protocol.Effect{{Kind: protocol.RunHook, Message: diam.NewRequest(diam.DeviceWatchdog, 0, c.Dictionary())}}, batch.effects...)
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				state.run(batch)
			}()
			sm.mux = mux
			var wantPanic any
			if item.flags&16 != 0 {
				wantPanic = "synthetic pre-admit panic"
			} else if item.flags&4 != 0 && item.flags&8 == 0 {
				wantPanic = "synthetic handler panic"
			}
			if recovered != wantPanic {
				t.Fatalf("batch panic=%v; want=%v", recovered, wantPanic)
			}
			for len(c.writes) > 0 {
				<-c.writes
			}
		}
		for i, op := range operations {
			flags := uint8(0)
			if op&1 != 0 {
				flags = diam.RequestFlag
			}
			m := diam.NewMessage(0xeeff, flags, 1001, uint32(i+1), uint32(op)|0x100, c.Dictionary())
			item := committed{state.prepare(protocol.Input{Kind: protocol.Receive, Message: m}), op}
			admitted := false
			for _, effect := range item.batch.effects {
				admitted = admitted || effect.Kind == protocol.Admit
			}
			if !admitted {
				t.Fatalf("application message not admitted: flags=%02x effects=%v", flags, item.batch.effects)
			}
			if op&2 != 0 {
				run(item)
			} else {
				pending = append(pending, item)
				if op&1 != 0 {
					remaining++
				}
			}
		}
		probe := func(sequence uint32) {
			t.Helper()
			dpr := diam.NewMessage(diam.DisconnectPeer, diam.RequestFlag, 0, 100+sequence, 200+sequence, c.Dictionary())
			dpr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("saved.example")))
			dpr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			dpr.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
			state.apply(protocol.Input{Kind: protocol.Receive, Message: dpr})
			var wire []byte
			select {
			case wire = <-c.writes:
			default:
				t.Fatal("DPR did not produce a wire DPA")
			}
			dpa, err := diam.ReadMessage(bytes.NewReader(wire), c.Dictionary())
			want := uint32(diam.Success)
			if remaining > 0 {
				want = diam.UnableToComply
			}
			if err != nil || dpa.Header.CommandCode != diam.DisconnectPeer || dpa.Header.CommandFlags != 0 || dpa.Header.HopByHopID != dpr.Header.HopByHopID || dpa.Header.EndToEndID != dpr.Header.EndToEndID || !testResultCode(dpa, want) {
				t.Fatalf("remaining handlers=%d: DPA=%v error=%v; want Result-Code %d and DPR identifiers", remaining, dpa, err, want)
			}
		}
		probe(0)
		for i := len(pending) - 1; i >= 0; i-- {
			run(pending[i])
			if pending[i].flags&1 != 0 {
				remaining--
			}
			probe(uint32(len(pending) - i))
		}
	})
}
