package base_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

func fixtureSettings() base.Settings {
	return base.Settings{
		OriginHost: "local.example.net", OriginRealm: "example.net",
		VendorID: 42, ProductName: "base-test", OriginStateID: 123456,
		HostIPAddresses:   []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.1"))},
		AcctApplicationID: []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(0xffffffff))},
		Applications:      []base.LocalApplication{{ID: 0xffffffff, AppType: "acct"}},
	}
}

func TestBuildBaseRequests(t *testing.T) {
	cfg := fixtureSettings()
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	validateBuiltMessage(t, cer)
	if cer.Header.CommandCode != diam.CapabilitiesExchange {
		t.Fatalf("CER code = %d", cer.Header.CommandCode)
	}
	parsed := new(base.CER)
	if _, err := parsed.Parse(cer, base.ParseOptions{Role: base.Server}); err != nil {
		t.Fatal(err)
	}
	dwr, err := base.BuildDWR(dict.Default, cfg, 333)
	if err != nil {
		t.Fatal(err)
	}
	validateBuiltMessage(t, dwr)
	state, err := dwr.FindAVP(avp.OriginStateID, 0)
	if err != nil || state.Data != datatype.Unsigned32(333) {
		t.Fatalf("DWR state = %v, error = %v", state, err)
	}
	dpr, err := base.BuildDPR(dict.Default, cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	validateBuiltMessage(t, dpr)
	if cause, err := base.ValidateDPR(dpr); err != nil || cause != 1 {
		t.Fatalf("DPR cause = %d, error = %v", cause, err)
	}
}

func TestBuildBaseAnswersPreservesRequestIDs(t *testing.T) {
	cfg := fixtureSettings()
	for _, command := range []uint32{diam.CapabilitiesExchange, diam.DeviceWatchdog, diam.DisconnectPeer} {
		request := diam.NewMessage(command, diam.RequestFlag|diam.RetransmittedFlag, 0, 0x11223344, 0x55667788, dict.Default)
		var answer *diam.Message
		var err error
		switch command {
		case diam.CapabilitiesExchange:
			answer, err = base.BuildCEA(request, cfg, diam.Success)
		case diam.DeviceWatchdog:
			answer, err = base.BuildDWA(request, cfg)
		case diam.DisconnectPeer:
			answer, err = base.BuildDPA(request, cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		validateBuiltMessage(t, answer)
		if answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || answer.Header.CommandFlags != 0 {
			t.Fatalf("command %d answer header = %+v", command, answer.Header)
		}
	}
}

func TestCapabilityBuilderOutgoingFlags(t *testing.T) {
	cfg := fixtureSettings()
	cfg.FirmwareRevision = 1
	// A vendor-specific application makes the builders emit a
	// Vendor-Specific-Application-Id derived from the dictionary.
	cfg.AcctApplicationID = nil
	cfg.Applications = []base.LocalApplication{{ID: diam.TGPP_S6A_APP_ID, AppType: "auth", Vendor: 10415}}
	cer, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cea, err := base.BuildCEA(cer, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*diam.Message{cer, cea} {
		validateBuiltMessage(t, m)
		if _, err := m.FindAVP(avp.VendorSpecificApplicationID, 0); err != nil {
			t.Fatalf("command %d carries no Vendor-Specific-Application-Id: %v", m.Header.CommandCode, err)
		}
		for _, tc := range []struct {
			code  uint32
			flags uint8
		}{
			{avp.OriginHost, avp.Mbit}, {avp.OriginRealm, avp.Mbit},
			{avp.HostIPAddress, avp.Mbit}, {avp.VendorID, avp.Mbit},
			{avp.ProductName, 0}, {avp.FirmwareRevision, 0},
		} {
			a, err := m.FindAVP(tc.code, 0)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := a.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if wire[4] != tc.flags {
				t.Errorf("command flags %#x AVP %d: flags %#x, want %#x", m.Header.CommandFlags, tc.code, wire[4], tc.flags)
			}
		}
	}
}

func TestBuildProtocolAndPermanentErrorAnswers(t *testing.T) {
	cfg := fixtureSettings()
	request := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag|diam.RetransmittedFlag, 0, 1, 2, dict.Default)
	protocol, err := base.BuildErrorAnswer(request, cfg, diam.CommandUnsupported, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	validateBuiltMessage(t, protocol)
	if protocol.Header.CommandFlags != diam.ErrorFlag {
		t.Fatalf("protocol flags = %#x", protocol.Header.CommandFlags)
	}
	permanent, err := base.BuildErrorAnswer(request, cfg, diam.AVPUnsupported, []*diam.AVP{diam.NewAVP(9999, avp.Mbit, 0, datatype.OctetString("bad"))}, false)
	if err != nil {
		t.Fatal(err)
	}
	validateBuiltMessage(t, permanent)
	if permanent.Header.CommandFlags != 0 {
		t.Fatalf("permanent flags = %#x", permanent.Header.CommandFlags)
	}
	if _, err := permanent.FindAVP(avp.FailedAVP, 0); err != nil {
		t.Fatal(err)
	}
}

func TestBuildErrorCEAResolvesAddressesAtBuildTime(t *testing.T) {
	cfg := fixtureSettings()
	cfg.HostIPAddresses = nil
	called := false
	cfg.ResolveHostIPAddresses = func() ([]datatype.Address, error) {
		called = true
		return []datatype.Address{datatype.AddressFromIP(netip.MustParseAddr("127.0.0.3"))}, nil
	}
	request := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag, 0, 5, 6, dict.Default)
	answer, err := base.BuildErrorAnswer(request, cfg, diam.AVPUnsupported, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("local address resolver was not called")
	}
	addresses, err := answer.FindAVPs(avp.HostIPAddress, 0)
	if err != nil || len(addresses) != 1 {
		t.Fatalf("CEA addresses = %v, error = %v", addresses, err)
	}
}

func TestBuildErrorAnswerDoesNotReuseUndecodedSessionID(t *testing.T) {
	request := diam.NewRequest(diam.CreditControl, diam.CHARGING_CONTROL_APP_ID, dict.Default)
	request.Header.CommandFlags |= diam.ProxiableFlag
	malformed := diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.Unknown([]byte("undecoded")))
	request.AddAVP(malformed)
	answer, err := base.BuildErrorAnswer(request, fixtureSettings(), diam.InvalidAVPValue, []*diam.AVP{malformed}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.AVP) == 0 || answer.AVP[0].Code != avp.SessionID || answer.AVP[0].Data != datatype.UTF8String("") {
		t.Fatalf("answer reused undecoded Session-Id: %v", answer)
	}
}

func TestCapabilityBuildersRejectInvalidAddresses(t *testing.T) {
	for _, addr := range []datatype.Address{{}, {Family: datatype.AddressFamilyIPv4, Value: make([]byte, 16)}, {Value: []byte{192, 0, 2, 1}}} {
		cfg := fixtureSettings()
		cfg.HostIPAddresses = append(cfg.HostIPAddresses, addr)
		if m, err := base.BuildCER(dict.Default, cfg); err == nil || m != nil {
			t.Errorf("BuildCER accepted invalid Address %v", addr)
		}
		request := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
		for _, code := range []uint32{diam.Success, diam.NoCommonApplication} {
			if m, err := base.BuildCEA(request, cfg, code); err == nil || m != nil {
				t.Errorf("BuildCEA(%d) accepted invalid Address %v", code, addr)
			}
		}
	}
}

func TestCapabilityBuildersPreserveMappedFamily(t *testing.T) {
	cfg := fixtureSettings()
	address := datatype.Address{Family: datatype.AddressFamilyIPv6, Value: netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()}
	cfg.HostIPAddresses = []datatype.Address{address}
	request, err := base.BuildCER(dict.Default, cfg)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := base.BuildCEA(request, cfg, diam.Success)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*diam.Message{request, answer} {
		a, err := m.FindAVP(avp.HostIPAddress, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := a.Data.(datatype.Address)
		if !ok || got.Family != address.Family || !bytes.Equal(got.Value, address.Value) {
			t.Fatalf("builder changed mapped wire family: %v", a.Data)
		}
	}
}

func validateBuiltMessage(t *testing.T, m *diam.Message) {
	t.Helper()
	if err := m.ValidateOutgoing(); err != nil {
		t.Fatalf("outgoing %d: %v", m.Header.CommandCode, err)
	}
	wire, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), m.Dictionary())
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateOutgoing(); err != nil {
		t.Fatalf("serialized outgoing %d: %v", m.Header.CommandCode, err)
	}
}
