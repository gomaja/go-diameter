package diam

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §7.1.5: the first excess instance wins over fixed placement;
// §3.2 still requires the first occurrence in the command prefix.
func TestBaseFixedErrorPrecedence(t *testing.T) {
	_, commands := baseWireSpec(t)
	for _, c := range commands {
		if !c.Request || !c.Rules[0].Fixed {
			continue
		}
		t.Run(c.Section, func(t *testing.T) {
			for _, adjacent := range []bool{false, true} {
				m := baseCommandMessage(t, 0, c)
				excess := NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("first-excess"))
				m.AddAVP(excess)
				if adjacent {
					m.AVP[1], m.AVP[len(m.AVP)-1] = m.AVP[len(m.AVP)-1], m.AVP[1]
				}
				m.AddAVP(NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("later-excess")))
				if err := m.Validate(); err == nil || err.ResultCode != AVPOccursTooManyTimes || err.FailedAVP != excess {
					t.Fatalf("duplicate: %v", err)
				}
			}
			m := baseCommandMessage(t, 0, c)
			m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0]
			if err := m.Validate(); err == nil || err.ResultCode != AVPNotAllowed {
				t.Fatalf("displaced: %v", err)
			}
			m = baseCommandMessage(t, 0, c)
			m.AVP = m.AVP[1:]
			if err := m.Validate(); err == nil || err.ResultCode != MissingAVP || err.FailedAVP == nil || err.FailedAVP.Code != avp.SessionID || err.FailedAVP.Data.Len() != 0 {
				t.Fatalf("absent: %v", err)
			}
		})
	}
}

// RFC 6733 §3.2: arbitrary unlisted AVPs satisfy wildcard minima.
// Named members are counted separately; unknown M-bit handling is §4.1.
func TestBaseWildcardMinimum(t *testing.T) {
	for _, tc := range []struct {
		name  string
		codes []uint32
		min   int
		valid bool
	}{
		{"empty", nil, 1, false}, {"named only", []uint32{avp.OriginHost}, 1, false},
		{"unknown only", []uint32{999999}, 1, true}, {"known", []uint32{avp.UserName}, 1, true},
		{"two required mixed", []uint32{avp.UserName, 999999}, 2, true},
		{"two required two", []uint32{avp.UserName, avp.UserName}, 2, true},
		{"zero", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []*dict.Rule{{AVP: "Origin-Host", Max: 1}, {AVP: "AVP", Min: tc.min}}
			var items []*AVP
			for _, code := range tc.codes {
				items = append(items, NewAVP(code, 0, 0, datatype.OctetString("x")))
			}
			err := validateAVPs(items, rules, 0, dict.Default.Snapshot())
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.ResultCode != MissingAVP {
				t.Fatalf("minimum: %v", err)
			}
		})
	}
}

// RFC 6733 §7.5: Failed-AVP must contain evidence, including unknown or
// malformed peer AVPs. It must not recursively apply the sender's grammar.
func TestBaseFailedEvidenceMinimum(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence []*AVP
		valid    bool
	}{
		{"empty", nil, false}, {"nil member", []*AVP{nil}, false},
		{"unknown mandatory", []*AVP{NewAVP(999999, avp.Mbit, 0, datatype.Unknown{1})}, true},
		{"bad flags", []*AVP{NewAVP(avp.UserName, 0xff, 0, datatype.Unknown{1})}, true},
		{"empty nested group", []*AVP{NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{})}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMessage(DeviceWatchdog, 0, 0, 1, 2, dict.Default)
			m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(AVPUnsupported)))
			m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
			m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
			m.AddAVP(NewAVP(avp.FailedAVP, avp.Mbit, 0, &GroupedAVP{}))
			m.AVP[len(m.AVP)-1].Data = &GroupedAVP{AVP: tc.evidence}
			for _, check := range []func() *ValidationError{m.Validate, m.ValidateOutgoing} {
				err := check()
				if tc.valid {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("empty or nil evidence accepted")
				}
			}
			if tc.valid {
				wire, err := m.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				got, err := ReadMessage(bytes.NewReader(wire), dict.Default)
				if err != nil {
					t.Fatal(err)
				}
				if err := got.ValidateOutgoing(); err != nil {
					t.Fatal(err)
				}
				again, err := got.Serialize()
				if err != nil || !bytes.Equal(wire, again) {
					t.Fatalf("evidence changed: %v", err)
				}
			}
		})
	}
}

func baseMissingAnswer() *Message {
	m := NewMessage(ReAuth, ProxiableFlag, 0, 1, 2, dict.Default)
	m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(MissingAVP)))
	m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	m.AddAVP(NewAVP(avp.FailedAVP, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(""))}}))
	return m
}

// RFC 6733 §§6.2 and 7.1.5: error answers can omit Session-Id
// independently of Failed-AVP evidence, while all other rules still apply.
func TestBaseMissingSessionAnswerScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Message)
		valid  bool
	}{
		{"missing session", func(*Message) {}, true},
		{"success", func(m *Message) { m.AVP[0].Data = datatype.Unsigned32(Success) }, false},
		{"other error", func(m *Message) { m.AVP[0].Data = datatype.Unsigned32(AVPUnsupported) }, true},
		{"no evidence", func(m *Message) { m.AVP = m.AVP[:3] }, true},
		{"other evidence", func(m *Message) { m.AVP[3].Data.(*GroupedAVP).AVP[0].Code = avp.UserName }, true},
		{"nonempty example", func(m *Message) { m.AVP[3].Data.(*GroupedAVP).AVP[0].Data = datatype.UTF8String("existing") }, true},
		{"missing origin", func(m *Message) { m.AVP = append(m.AVP[:1], m.AVP[2:]...) }, false},
		{"duplicate origin", func(m *Message) { m.AddAVP(m.AVP[1]) }, false},
		{"displaced session", func(m *Message) { m.AddAVP(NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("late"))) }, false},
		{"request", func(m *Message) { m.Header.CommandFlags |= RequestFlag }, false},
		{"duplicate evidence", func(m *Message) { m.AddAVP(m.AVP[3]) }, false},
		{"multiple examples", func(m *Message) { g := m.AVP[3].Data.(*GroupedAVP); g.AVP = append(g.AVP, g.AVP[0]) }, true},
		{"vendor example", func(m *Message) { m.AVP[3].Data.(*GroupedAVP).AVP[0].VendorID = 42 }, true},
		{"wrong example type", func(m *Message) { m.AVP[3].Data.(*GroupedAVP).AVP[0].Data = datatype.OctetString("") }, true},
		{"accounting fields missing", func(m *Message) { m.Header.CommandCode = Accounting }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := baseMissingAnswer()
			tc.change(m)
			for _, check := range []func() *ValidationError{m.Validate} {
				err := check()
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%t: %v", tc.valid, err)
				}
			}
		})
	}
}

// RFC 6733 §7.2: optional Session-Id is fixed, and a second instance is 5009.
func TestBaseProtocolErrorSessionPrefix(t *testing.T) {
	for _, kind := range []string{"absent", "first", "late", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			m := baseMissingAnswer()
			m.AVP = m.AVP[:3]
			m.Header.CommandFlags |= ErrorFlag
			m.AVP[0].Data = datatype.Unsigned32(InvalidHDRBits)
			session := NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("session"))
			switch kind {
			case "first", "duplicate":
				m.InsertAVP(session)
			case "late":
				m.AddAVP(session)
			}
			if kind == "duplicate" {
				m.AddAVP(session)
			}
			err := m.ValidateOutgoing()
			switch kind {
			case "absent", "first":
				if err != nil {
					t.Fatal(err)
				}
			case "late":
				if err == nil || err.ResultCode != AVPNotAllowed {
					t.Fatalf("late: %v", err)
				}
			case "duplicate":
				if err == nil || err.ResultCode != AVPOccursTooManyTimes {
					t.Fatalf("duplicate: %v", err)
				}
			}
		})
	}
}

// RFC 6733 §§3.2 and 7.5: a missing arbitrary member has no AVP code;
// retain its parent as a serializable empty example in Failed-AVP.
func TestBaseNestedWildcardMinimum(t *testing.T) {
	d, parseErr := dict.NewParser()
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	xml := strings.Replace(validationDictionary, `<rule avp="Child" required="true" max="1"/>`, `<rule avp="AVP" required="true" min="1"/>`, 1)
	if err := d.Load(strings.NewReader(xml)); err != nil {
		t.Fatal(err)
	}
	m := NewMessage(999, RequestFlag|ProxiableFlag, 0, 1, 2, d)
	m.AddAVP(NewAVP(1, avp.Mbit, 0, datatype.Unsigned32(1)))
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(2)))
	m.AddAVP(NewAVP(3, avp.Mbit, 0, &GroupedAVP{}))
	err := m.ValidateOutgoing()
	if err == nil || err.ResultCode != MissingAVP || err.FailedAVP == nil || err.FailedAVP.Code != 3 {
		t.Fatalf("missing extension: %v", err)
	}
	g, ok := err.FailedAVP.Data.(*GroupedAVP)
	if !ok || len(g.AVP) != 0 {
		t.Fatalf("parent example: %v", err.FailedAVP)
	}
	if _, err := NewAVP(avp.FailedAVP, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{err.FailedAVP}}).Serialize(); err != nil {
		t.Fatal(err)
	}
}

func FuzzBaseWildcardMinimum(f *testing.F) {
	f.Add([]byte{0, 1, 2}, uint8(1))
	f.Add([]byte{}, uint8(1))
	f.Fuzz(func(t *testing.T, input []byte, minimum uint8) {
		if len(input) > 64 {
			t.Skip()
		}
		rules := []*dict.Rule{{AVP: "Origin-Host"}, {AVP: "AVP", Min: int(minimum)}}
		var items []*AVP
		count := 0
		for _, v := range input {
			code := uint32(999999)
			switch v % 3 {
			case 0:
				code = avp.OriginHost
			case 1:
				code = avp.UserName
				count++
			default:
				count++
			}
			items = append(items, NewAVP(code, 0, 0, datatype.OctetString("x")))
		}
		err := validateAVPs(items, rules, 0, dict.Default.Snapshot())
		if count >= int(minimum) {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || err.ResultCode != MissingAVP {
			t.Fatalf("count %d minimum %d: %v", count, minimum, err)
		}
	})
}

// Failed-AVP is a Grouped container even though its evidence is opaque (§7.5).
func TestBaseFailedEvidenceContainer(t *testing.T) {
	for _, data := range []datatype.Type{nil, datatype.Unknown{}, (*GroupedAVP)(nil)} {
		m := baseMissingAnswer()
		m.Header.CommandCode = DeviceWatchdog
		m.Header.CommandFlags = 0
		m.AVP[3].Data = data
		for _, check := range []func() *ValidationError{m.Validate, m.ValidateOutgoing} {
			if err := check(); err == nil || err.ResultCode != InvalidAVPValue {
				t.Fatalf("invalid container: %v", err)
			}
		}
	}
}
