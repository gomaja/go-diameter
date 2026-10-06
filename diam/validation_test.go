package diam

import (
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

const validationDictionary = `<diameter><application id="0" name="test">
<command code="999" name="Test" short="TE"><request proxiable="true">
<rule avp="Fixed" required="true" max="1" fixed="true"/>
<rule avp="Required" required="true" max="1"/>
<rule avp="Group" max="1"/>
</request><answer proxiable="true"><rule avp="Result" required="true" max="1"/></answer></command>
<avp name="Fixed" code="1" must="M" must-not="V,P"><data type="Unsigned32"/></avp>
<avp name="Required" code="2" must="M" must-not="V,P"><data type="Unsigned32"/></avp>
<avp name="Group" code="3" must="M" must-not="V,P"><data type="Grouped">
<rule avp="Child" required="true" max="1"/></data></avp>
<avp name="Child" code="4" must="V,M" must-not="P" vendor-id="42"><data type="Unsigned32"/></avp>
<avp name="Result" code="5" must="M" must-not="V,P"><data type="Unsigned32"/></avp>
<avp name="Forbidden" code="6" must="M" must-not="V,P"><data type="Unsigned32"/></avp>
</application></diameter>`

func validationFixture(t *testing.T) (*Message, *dict.Parser) {
	t.Helper()
	d, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(validationDictionary)); err != nil {
		t.Fatal(err)
	}
	m := NewMessage(999, RequestFlag|ProxiableFlag, 0, 1, 2, d)
	m.AddAVP(NewAVP(1, avp.Mbit, 0, datatype.Unsigned32(1)))
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(2)))
	return m, d
}

func TestValidateDictionaryRules(t *testing.T) {
	for _, tc := range []struct {
		name       string
		change     func(*Message)
		code       uint32
		failedCode uint32
	}{
		{"valid", func(*Message) {}, 0, 0},
		{"missing", func(m *Message) { m.AVP = m.AVP[:1] }, MissingAVP, 2},
		{"too many", func(m *Message) { m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(3))) }, AVPOccursTooManyTimes, 2},
		{"not allowed", func(m *Message) { m.AddAVP(NewAVP(6, avp.Mbit, 0, datatype.Unsigned32(1))) }, AVPNotAllowed, 6},
		{"unknown optional AVP ignored", func(m *Message) { m.AddAVP(NewAVP(77, 0, 0, datatype.Unknown{1})) }, 0, 0},
		{"unknown mandatory AVP left to 5001", func(m *Message) { m.AddAVP(NewAVP(78, avp.Mbit, 0, datatype.Unknown{1})) }, 0, 0},
		{"fixed position", func(m *Message) { m.AVP[0], m.AVP[1] = m.AVP[1], m.AVP[0] }, AVPNotAllowed, 2},
		{"missing M", func(m *Message) { m.AVP[0].Flags = 0 }, InvalidAVPBits, 1},
		{"forbidden P", func(m *Message) { m.AVP[0].Flags |= avp.Pbit }, InvalidAVPBits, 1},
		{"forbidden V", func(m *Message) { m.AVP[0].Flags |= avp.Vbit }, InvalidAVPBits, 1},
		{"request E", func(m *Message) { m.Header.CommandFlags |= ErrorFlag }, InvalidHDRBits, 0},
		{"missing P", func(m *Message) { m.Header.CommandFlags &^= ProxiableFlag }, InvalidHDRBits, 0},
		{"unknown command", func(m *Message) { m.Header.CommandCode = 0xfedc }, CommandUnsupported, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := validationFixture(t)
			tc.change(m)
			got := m.Validate()
			if tc.code == 0 {
				if got != nil {
					t.Fatalf("unexpected validation error: %v", got)
				}
				return
			}
			if got == nil || got.ResultCode != tc.code {
				t.Fatalf("got %v, want %d", got, tc.code)
			}
			if tc.failedCode != 0 && (got.FailedAVP == nil || got.FailedAVP.Code != tc.failedCode) {
				t.Fatalf("Failed-AVP = %v, want code %d", got.FailedAVP, tc.failedCode)
			}
			if tc.name == "too many" && got.FailedAVP != m.AVP[2] {
				t.Fatal("Failed-AVP must be first excess instance")
			}
			if tc.name == "missing" && (got.FailedAVP.VendorID != 0 || len(got.FailedAVP.Data.Serialize()) != 4) {
				t.Fatalf("missing example = %v", got.FailedAVP)
			}
		})
	}
}

func TestValidateAnswerGrammar(t *testing.T) {
	_, dictionary := validationFixture(t)
	m := NewMessage(999, ProxiableFlag, 0, 1, 2, dictionary)
	if got := m.Validate(); got == nil || got.ResultCode != MissingAVP || got.FailedAVP.Code != 5 {
		t.Fatalf("missing answer Result: %v", got)
	}
	m.AddAVP(NewAVP(5, avp.Mbit, 0, datatype.Unsigned32(2001)))
	if got := m.Validate(); got != nil {
		t.Fatalf("valid answer: %v", got)
	}
}

func TestValidateExplicitZeroMaximum(t *testing.T) {
	dictionaryXML := strings.Replace(validationDictionary, `<rule avp="Group" max="1"/>`, `<rule avp="Group" max="0"/>`, 1)
	d, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(dictionaryXML)); err != nil {
		t.Fatal(err)
	}
	m := NewMessage(999, RequestFlag|ProxiableFlag, 0, 1, 2, d)
	m.AddAVP(NewAVP(1, avp.Mbit, 0, datatype.Unsigned32(1)))
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(2)))
	m.AddAVP(NewAVP(3, avp.Mbit, 0, &GroupedAVP{}))
	if got := m.Validate(); got == nil || got.ResultCode != AVPNotAllowed || got.FailedAVP != m.AVP[2] {
		t.Fatalf("zero maximum: %v", got)
	}
}

func TestValidateVendorApplicationChoice(t *testing.T) {
	for _, tc := range []struct {
		name     string
		children []*AVP
		code     uint32
	}{
		{"missing-both", []*AVP{NewAVP(266, avp.Mbit, 0, datatype.Unsigned32(10415))}, MissingAVP},
		{"both", []*AVP{NewAVP(266, avp.Mbit, 0, datatype.Unsigned32(10415)), NewAVP(258, avp.Mbit, 0, datatype.Unsigned32(1)), NewAVP(259, avp.Mbit, 0, datatype.Unsigned32(1))}, AVPOccursTooManyTimes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMessage(CapabilitiesExchange, RequestFlag, 0, 1, 2, dict.Default)
			for _, a := range []*AVP{
				NewAVP(264, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")),
				NewAVP(296, avp.Mbit, 0, datatype.DiameterIdentity("example")),
				NewAVP(257, avp.Mbit, 0, datatype.Address{127, 0, 0, 1}),
				NewAVP(266, avp.Mbit, 0, datatype.Unsigned32(1)),
				NewAVP(269, 0, 0, datatype.UTF8String("product")),
				NewAVP(260, avp.Mbit, 0, &GroupedAVP{AVP: tc.children}),
			} {
				m.AddAVP(a)
			}
			got := m.Validate()
			if got == nil || got.ResultCode != tc.code || got.FailedAVP == nil || got.FailedAVP.Code != 260 {
				t.Fatalf("VSA choice = %v", got)
			}
		})
	}
}

func TestValidateGenericProtocolError(t *testing.T) {
	m := NewMessage(0xfedc, ErrorFlag|ProxiableFlag, 0, 1, 2, dict.Default)
	m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(InvalidHDRBits)))
	if got := m.Validate(); got == nil || got.ResultCode != MissingAVP || got.FailedAVP.Code != avp.OriginHost {
		t.Fatalf("incomplete generic error answer: %v", got)
	}
	m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if got := m.Validate(); got != nil {
		t.Fatalf("valid generic error answer: %v", got)
	}
}

func TestValidateBaseDPRRequiresCause(t *testing.T) {
	m := NewRequest(DisconnectPeer, 0, dict.Default)
	m.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	m.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if got := m.Validate(); got == nil || got.ResultCode != MissingAVP || got.FailedAVP.Code != avp.DisconnectCause {
		t.Fatalf("missing Disconnect-Cause: %v", got)
	}
}

func TestValidateTwoLevelGroupedHierarchy(t *testing.T) {
	xml := strings.Replace(validationDictionary, `<data type="Unsigned32"/></avp>
<avp name="Result"`, `<data type="Grouped"><rule avp="Leaf" required="true" max="1"/></data></avp>
<avp name="Leaf" code="7" must="M" must-not="V,P"><data type="Unsigned32"/></avp>
<avp name="Result"`, 1)
	d, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(xml)); err != nil {
		t.Fatal(err)
	}
	m := NewMessage(999, RequestFlag|ProxiableFlag, 0, 1, 2, d)
	m.AddAVP(NewAVP(1, avp.Mbit, 0, datatype.Unsigned32(1)))
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(2)))
	m.AddAVP(NewAVP(3, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{NewAVP(4, avp.Vbit|avp.Mbit, 42, &GroupedAVP{})}}))
	got := m.Validate()
	if got == nil || got.ResultCode != MissingAVP {
		t.Fatalf("nested missing leaf: %v", got)
	}
	first := got.FailedAVP.Data.(*GroupedAVP).AVP
	second := first[0].Data.(*GroupedAVP).AVP
	if got.FailedAVP.Code != 3 || first[0].Code != 4 || len(second) != 1 || second[0].Code != 7 {
		t.Fatalf("nested Failed-AVP: %v", got.FailedAVP)
	}
}

func TestValidateMissingGroupedExample(t *testing.T) {
	xml := strings.Replace(validationDictionary, `<rule avp="Group" max="1"/>`, `<rule avp="Group" required="true" max="1"/>`, 1)
	d, err := dict.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Load(strings.NewReader(xml)); err != nil {
		t.Fatal(err)
	}
	m := NewMessage(999, RequestFlag|ProxiableFlag, 0, 1, 2, d)
	m.AddAVP(NewAVP(1, avp.Mbit, 0, datatype.Unsigned32(1)))
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(2)))
	got := m.Validate()
	if got == nil || got.ResultCode != MissingAVP || got.FailedAVP.Code != 3 {
		t.Fatalf("missing grouped AVP: %v", got)
	}
	children, ok := got.FailedAVP.Data.(*GroupedAVP)
	if !ok || len(children.AVP) != 1 || children.AVP[0].Code != 4 || children.AVP[0].VendorID != 42 {
		t.Fatalf("group example: %v", got.FailedAVP)
	}
}

func TestValidateProgrammaticMaximum(t *testing.T) {
	m, d := validationFixture(t)
	command, err := d.FindCommand(0, 999)
	if err != nil {
		t.Fatal(err)
	}
	command.Request.Rule[1].MaxSet = false
	m.AddAVP(NewAVP(2, avp.Mbit, 0, datatype.Unsigned32(3)))
	if got := m.Validate(); got == nil || got.ResultCode != AVPOccursTooManyTimes {
		t.Fatalf("programmatic maximum: %v", got)
	}
}

func TestValidateCreditControlFixedSessionID(t *testing.T) {
	request := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
	request.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	request.AddAVP(NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("session")))
	request.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	request.AddAVP(NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	request.AddAVP(NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	request.AddAVP(NewAVP(avp.ServiceContextID, avp.Mbit, 0, datatype.UTF8String("service")))
	request.AddAVP(NewAVP(avp.CCRequestType, avp.Mbit, 0, datatype.Enumerated(1)))
	request.AddAVP(NewAVP(avp.CCRequestNumber, avp.Mbit, 0, datatype.Unsigned32(7)))
	if got := request.Validate(); got == nil || got.ResultCode != AVPNotAllowed || got.FailedAVP != request.AVP[0] {
		t.Fatalf("CCR fixed Session-Id: %v", got)
	}
	answer := NewMessage(CreditControl, ProxiableFlag, 4, 1, 2, dict.Default)
	answer.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(Success)))
	answer.AddAVP(NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("session")))
	answer.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("server.example")))
	answer.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	answer.AddAVP(NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)))
	answer.AddAVP(NewAVP(avp.CCRequestType, avp.Mbit, 0, datatype.Enumerated(1)))
	answer.AddAVP(NewAVP(avp.CCRequestNumber, avp.Mbit, 0, datatype.Unsigned32(7)))
	if got := answer.Validate(); got == nil || got.ResultCode != AVPNotAllowed || got.FailedAVP != answer.AVP[0] {
		t.Fatalf("CCA fixed Session-Id: %v", got)
	}
}

func TestValidateCreditControlExtensionAVP(t *testing.T) {
	request := NewMessage(CreditControl, RequestFlag|ProxiableFlag, 4, 1, 2, dict.Default)
	for _, field := range []struct {
		code  uint32
		value datatype.Type
	}{
		{avp.SessionID, datatype.UTF8String("session")},
		{avp.OriginHost, datatype.DiameterIdentity("peer.example")},
		{avp.OriginRealm, datatype.DiameterIdentity("example")},
		{avp.DestinationRealm, datatype.DiameterIdentity("example")},
		{avp.AuthApplicationID, datatype.Unsigned32(4)},
		{avp.ServiceContextID, datatype.UTF8String("service")},
		{avp.CCRequestType, datatype.Enumerated(1)},
		{avp.CCRequestNumber, datatype.Unsigned32(7)},
	} {
		request.AddAVP(NewAVP(field.code, avp.Mbit, 0, field.value))
	}
	request.AddAVP(NewAVP(0xdead, 0, 0, datatype.OctetString("extension")))
	if got := request.Validate(); got != nil {
		t.Fatalf("RFC 8506 CCR extension: %v", got)
	}
}

func TestValidateNestedGrouped(t *testing.T) {
	m, _ := validationFixture(t)
	group := NewAVP(3, avp.Mbit, 0, &GroupedAVP{})
	m.AddAVP(group)
	got := m.Validate()
	if got == nil || got.ResultCode != MissingAVP || got.FailedAVP == nil || got.FailedAVP.Code != 3 {
		t.Fatalf("missing child: %v", got)
	}
	children := got.FailedAVP.Data.(*GroupedAVP).AVP
	if len(children) != 1 || children[0].Code != 4 || children[0].VendorID != 42 || len(children[0].Data.Serialize()) != 4 {
		t.Fatalf("missing child example: %v", children)
	}
	group.Data = &GroupedAVP{AVP: []*AVP{NewAVP(4, avp.Vbit|avp.Mbit, 42, datatype.Unsigned32(1))}}
	if got = m.Validate(); got != nil {
		t.Fatalf("valid group: %v", got)
	}
	group.Data.(*GroupedAVP).AVP = append(group.Data.(*GroupedAVP).AVP, NewAVP(4, avp.Vbit|avp.Mbit, 42, datatype.Unsigned32(2)))
	if got = m.Validate(); got == nil || got.ResultCode != AVPOccursTooManyTimes || got.FailedAVP.Code != 3 {
		t.Fatalf("excess child: %v", got)
	}
}
