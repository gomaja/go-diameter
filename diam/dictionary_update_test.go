package diam

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

const updateTestVendor = 99999 // An enterprise number no bundled dictionary uses.

// updateTestCodes returns the codes change i defines: a UTF8String AVP, a
// Grouped AVP and the Unsigned32 member of the Grouped AVP.
func updateTestCodes(i int) (text, group, member uint32) {
	base := 70000 + 3*uint32(i)
	return base, base + 1, base + 2
}

// applyUpdateTestChange defines the AVPs of change i in application 4,
// registering them for an even i and loading them from XML for an odd one.
func applyUpdateTestChange(p *dict.Parser, i int) error {
	text, group, member := updateTestCodes(i)
	if i%2 == 1 {
		return p.Load(strings.NewReader(fmt.Sprintf(`<diameter><application id="4" type="auth" name="Update-%[1]d">
			<avp name="Update-Text-%[1]d" code="%[2]d" must="V" must-not="M" vendor-id="%[5]d"><data type="UTF8String"/></avp>
			<avp name="Update-Group-%[1]d" code="%[3]d" must="V" must-not="M" vendor-id="%[5]d"><data type="Grouped">
				<rule avp="Update-Member-%[1]d" required="true" max="1"/>
			</data></avp>
			<avp name="Update-Member-%[1]d" code="%[4]d" must="V" must-not="M" vendor-id="%[5]d"><data type="Unsigned32"/></avp>
		</application></diameter>`, i, text, group, member, updateTestVendor)))
	}
	avp := func(name string, code uint32, typ string) *dict.AVP {
		return &dict.AVP{Name: fmt.Sprintf("Update-%s-%d", name, i), Code: code, VendorID: updateTestVendor,
			Must: "V", MustNot: "M", Data: dict.Data{TypeName: typ}}
	}
	g := avp("Group", group, "Grouped")
	g.Data.Rule = []*dict.Rule{{AVP: fmt.Sprintf("Update-Member-%d", i), Required: true, Max: 1}}
	return p.RegisterAVP(4, avp("Text", text, "UTF8String"), g, avp("Member", member, "Unsigned32"))
}

// updateTestMessage is a CCR carrying, for each change, its text AVP and
// its Grouped AVP with the member inside.
func updateTestMessage(t *testing.T, p *dict.Parser, changes int) []byte {
	m := NewRequest(CreditControl, 4, p)
	for i := range changes {
		text, group, member := updateTestCodes(i)
		m.AddAVP(NewAVP(text, 0, updateTestVendor, datatype.UTF8String(fmt.Sprint("text-", i))))
		m.AddAVP(NewAVP(group, 0, updateTestVendor, &GroupedAVP{AVP: []*AVP{
			NewAVP(member, 0, updateTestVendor, datatype.Unsigned32(i)),
		}}))
	}
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// appliedUpdateTestChanges reports how many changes the decode of m saw,
// or an error if it saw a change partly, or a change without an earlier one.
func appliedUpdateTestChanges(m *Message, changes int) (int, error) {
	if len(m.AVP) != 2*changes {
		return 0, fmt.Errorf("%d AVPs, want %d", len(m.AVP), 2*changes)
	}
	applied := 0
	for i := range changes {
		text, group := m.AVP[2*i], m.AVP[2*i+1]
		var textKnown, groupKnown bool
		switch v := text.Data.(type) {
		case datatype.UTF8String:
			if string(v) != fmt.Sprint("text-", i) {
				return 0, fmt.Errorf("change %d: text %q", i, v)
			}
			textKnown = true
		case datatype.Unknown:
		default:
			return 0, fmt.Errorf("change %d: text decoded as %T", i, v)
		}
		switch v := group.Data.(type) {
		case *GroupedAVP:
			if len(v.AVP) != 1 {
				return 0, fmt.Errorf("change %d: %d members", i, len(v.AVP))
			}
			if n, ok := v.AVP[0].Data.(datatype.Unsigned32); !ok || int(n) != i {
				return 0, fmt.Errorf("change %d: member decoded as %T %v", i, v.AVP[0].Data, v.AVP[0].Data)
			}
			groupKnown = true
		case datatype.Unknown:
		default:
			return 0, fmt.Errorf("change %d: group decoded as %T", i, v)
		}
		switch {
		case textKnown != groupKnown:
			return 0, fmt.Errorf("change %d seen in part: text %t, group %t", i, textKnown, groupKnown)
		case textKnown && applied != i:
			return 0, fmt.Errorf("change %d seen without change %d", i, applied)
		case textKnown:
			applied++
		}
	}
	return applied, nil
}

// TestReadMessageWhileDictionaryChanges decodes one message in many
// goroutines while the dictionary gains the definitions of its AVPs, one
// change at a time, alternately loaded and registered. Each decode must see
// the dictionary before or after each change, never part of one: the
// changes it sees are a prefix of the sequence, each with all its AVPs.
// Run with -race.
func TestReadMessageWhileDictionaryChanges(t *testing.T) {
	const changes, decoders = 16, 8
	p := dict.New(dict.Base, dict.CreditControl, dict.RoRf, dict.NASREQ)
	wire := updateTestMessage(t, p, changes)

	var (
		wg      sync.WaitGroup
		done    atomic.Bool
		decodes atomic.Int64
		seen    [changes + 1]atomic.Int64 // decodes by number of changes seen
	)
	errs := make(chan error, decoders)
	for range decoders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for last := false; !last; {
				last = done.Load()
				m, err := ReadMessage(bytes.NewReader(wire), p)
				if err == nil {
					var n int
					if n, err = appliedUpdateTestChanges(m, changes); err == nil {
						seen[n].Add(1)
						decodes.Add(1)
						continue
					}
				}
				errs <- err
				return
			}
		}()
	}
	for i := range changes {
		for decodes.Load() < int64(i+1)*decoders { // let decodes overlap every change
			select {
			case err := <-errs:
				t.Fatal(err)
			default:
			}
		}
		if err := applyUpdateTestChange(p, i); err != nil {
			t.Fatal(err)
		}
	}
	done.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	m, err := ReadMessage(bytes.NewReader(wire), p)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := appliedUpdateTestChanges(m, changes); err != nil || n != changes {
		t.Fatalf("after every change: %d seen, %v", n, err)
	}
	var counts []int64
	for i := range seen {
		counts = append(counts, seen[i].Load())
	}
	t.Logf("%d decodes; by number of changes seen: %v", decodes.Load(), counts)
}

// TestRegisteredGroupedAVPDecodesAndValidates sends a message with a
// registered Grouped AVP through ReadMessage and Validate: its member rules
// apply like those of a loaded Grouped AVP.
func TestRegisteredGroupedAVPDecodesAndValidates(t *testing.T) {
	p := dict.New(dict.Base, dict.CreditControl, dict.RoRf, dict.NASREQ)
	if err := applyUpdateTestChange(p, 0); err != nil {
		t.Fatal(err)
	}
	text, group, member := updateTestCodes(0)
	build := func(members ...*AVP) *Message {
		m := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 0, 0, p)
		for _, a := range []struct {
			code uint32
			data datatype.Type
		}{
			{263, datatype.UTF8String("session;1")},
			{264, datatype.DiameterIdentity("client.example")},
			{296, datatype.DiameterIdentity("example")},
			{283, datatype.DiameterIdentity("example")},
			{258, datatype.Unsigned32(4)},
			{461, datatype.UTF8String("32251@3gpp.org")},
			{416, datatype.Enumerated(1)},
			{415, datatype.Unsigned32(0)},
		} {
			m.AddAVP(NewAVP(a.code, 0x40, 0, a.data))
		}
		m.AddAVP(NewAVP(text, 0, updateTestVendor, datatype.UTF8String("text-0")))
		m.AddAVP(NewAVP(group, 0, updateTestVendor, &GroupedAVP{AVP: members}))
		b, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadMessage(bytes.NewReader(b), p)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	valid := build(NewAVP(member, 0, updateTestVendor, datatype.Unsigned32(0)))
	if _, ok := valid.AVP[len(valid.AVP)-1].Data.(*GroupedAVP); !ok {
		t.Fatalf("registered Grouped AVP decoded as %T", valid.AVP[len(valid.AVP)-1].Data)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	// The member rule is required, max 1 (RFC 6733 §7.1.5: 5005, 5009).
	if err := build().Validate(); err == nil || err.ResultCode != MissingAVP {
		t.Fatalf("missing member: Validate() = %v, want %d", err, MissingAVP)
	}
	twice := build(NewAVP(member, 0, updateTestVendor, datatype.Unsigned32(0)), NewAVP(member, 0, updateTestVendor, datatype.Unsigned32(1)))
	if err := twice.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes {
		t.Fatalf("member twice: Validate() = %v, want %d", err, AVPOccursTooManyTimes)
	}
}

// Undeclared applications do not acquire parents from their numeric IDs.
// Loaded and registered AVPs outside base remain unknown (RFC 6733 §4.1).
func TestDecodeDoesNotInheritInUndeclaredApplication(t *testing.T) {
	const gx = 16777238
	text, _, _ := updateTestCodes(1)
	registered := dict.New(dict.Base)
	if err := registered.RegisterAVP(4, &dict.AVP{Name: "Update-Text-1", Code: text, VendorID: updateTestVendor,
		Must: "M,V", Data: dict.Data{TypeName: "UTF8String"}}); err != nil {
		t.Fatal(err)
	}
	loaded := dict.New(dict.Base)
	if err := applyUpdateTestChange(loaded, 1); err != nil { // loads application 4
		t.Fatal(err)
	}
	for name, p := range map[string]*dict.Parser{"registered": registered, "loaded": loaded} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.App(gx); err == nil {
				t.Fatal("the dictionary declares Gx")
			}
			a := NewAVP(text, 0x40, updateTestVendor, datatype.UTF8String("text-1"))
			raw, err := a.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeAVP(raw, gx, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := decoded.Data.(datatype.Unknown); !ok {
				t.Errorf("DecodeAVP: %T, want Unknown", decoded.Data)
			}
			m := NewRequest(CreditControl, gx, p)
			m.AddAVP(a)
			wire, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			read, err := ReadMessage(bytes.NewReader(wire), p)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := read.AVP[0].Data.(datatype.Unknown); !ok {
				t.Errorf("ReadMessage: %T, want Unknown", read.AVP[0].Data)
			}
			if unknown := read.UnknownMandatoryAVPs(); len(unknown) != 1 || unknown[0].Code != text {
				t.Errorf("unknown mandatory AVPs: %v", unknown)
			}
		})
	}
}
