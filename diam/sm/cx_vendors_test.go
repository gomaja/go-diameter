package sm

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type capabilityGroup struct {
	app, vendor, kind uint32
}

func TestCapabilityConfigurationValidationBoundaries(t *testing.T) {
	invalid := diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
	}})
	settings := *serverSettings
	settings.VendorSpecificApplicationID = []*diam.AVP{invalid}
	if _, err := New(&settings); err == nil || !strings.Contains(err.Error(), "exactly one Vendor-Id") {
		t.Fatalf("sm.New malformed VSAI error = %v", err)
	}
	client := &Client{Handler: mustNew(serverSettings), VendorSpecificApplicationID: []*diam.AVP{invalid}}
	if _, err := client.Dial("127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "exactly one Vendor-Id") {
		t.Fatalf("Client.Dial malformed VSAI error = %v", err)
	}
}

func TestClientCapabilitiesSnapshotPrecedesTransport(t *testing.T) {
	dictionary := dict.New(dict.Base)
	if err := dictionary.Load(strings.NewReader(`<diameter><application id="16777999" type="auth" name="Private"/></diameter>`)); err != nil {
		t.Fatal(err)
	}
	settings := *clientSettings
	settings.Dict = dictionary
	client := &Client{Handler: mustNew(&settings), Dict: dictionary}
	stop := errors.New("transport stopped by test")
	_, err := client.dial(func(activity *watchdogActivity) (diam.Conn, error) {
		if !slices.Contains(activity.advertised, 16777999) {
			t.Fatalf("advertised applications unavailable before transport: %v", activity.advertised)
		}
		if err := dictionary.Load(strings.NewReader(`<diameter><application id="16777998" type="auth" name="Later"><vendor id="9999" name="Later"/></application></diameter>`)); err != nil {
			t.Fatal(err)
		}
		if ids := base.AdvertisedApplicationIDs(activity.capabilities); slices.Contains(ids, 16777998) {
			t.Fatalf("later Load changed connection capabilities: %v", ids)
		}
		cfg := activity.capabilities
		cfg.HostIPAddresses = []datatype.Address{localhostAddress}
		message, err := base.BuildCER(dictionary, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := readSMCapabilities(t, message, dictionary); slices.Contains(got.auth, 16777998) || !slices.Contains(got.auth, 16777999) {
			t.Fatalf("CER did not use captured applications: %+v", got)
		}
		return nil, stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("dial error = %v, want sentinel", err)
	}
}

type wireCapabilities struct {
	supported []uint32
	auth      []uint32
	acct      []uint32
	groups    []capabilityGroup
}

func readSMCapabilities(t *testing.T, message *diam.Message, dictionary *dict.Parser) wireCapabilities {
	t.Helper()
	wire, err := message.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diam.ReadMessage(bytes.NewReader(wire), dictionary)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	var got wireCapabilities
	for _, a := range decoded.AVP {
		switch a.Code {
		case avp.SupportedVendorID:
			got.supported = append(got.supported, uint32(a.Data.(datatype.Unsigned32)))
		case avp.AuthApplicationID:
			got.auth = append(got.auth, uint32(a.Data.(datatype.Unsigned32)))
		case avp.AcctApplicationID:
			got.acct = append(got.acct, uint32(a.Data.(datatype.Unsigned32)))
		case avp.VendorSpecificApplicationID:
			group := a.Data.(*diam.GroupedAVP)
			if len(group.AVP) != 2 || group.AVP[0].Code != avp.VendorID ||
				(group.AVP[1].Code != avp.AuthApplicationID && group.AVP[1].Code != avp.AcctApplicationID) {
				t.Fatalf("Vendor-Specific-Application-Id children = %v, want one Vendor-Id and one application ID", group.AVP)
			}
			got.groups = append(got.groups, capabilityGroup{
				app:    uint32(group.AVP[1].Data.(datatype.Unsigned32)),
				vendor: uint32(group.AVP[0].Data.(datatype.Unsigned32)),
				kind:   group.AVP[1].Code,
			})
		}
	}
	t.Logf("request=%t Supported-Vendor-Id=%v Auth=%v Acct=%v VSAI=%+v", message.Header.CommandFlags&diam.RequestFlag != 0, got.supported, got.auth, got.acct, got.groups)
	return got
}

func checkSMVendors(t *testing.T, got, want []uint32) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Supported-Vendor-Id = %v, want %v", got, want)
	}
}

func countSMGroup(groups []capabilityGroup, app, vendor, kind uint32) int {
	count := 0
	for _, group := range groups {
		if group.app == app && group.vendor == vendor && group.kind == kind {
			count++
		}
	}
	return count
}

func smVendorApp(id, vendor uint32) *diam.AVP {
	return diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor)),
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(id)),
	}})
}

func smSupportedVendor(id uint32) *diam.AVP {
	return diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(id))
}

// RFC 6733 §§5.3.6, 6.11 and TS 29.229 V19.1.0 §5.6: ETSI AVPs are
// supported for Cx, while 3GPP is the Cx application vendor.
func TestCxSupportedVendors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dictionary *dict.Parser
		offerCx    bool
		want       []uint32
	}{
		{"base-only", dict.New(dict.Base), false, nil},
		{"Cx", dict.New(dict.Base, dict.NASREQ, dict.Cx), true, []uint32{10415, 13019}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := *serverSettings
			settings.Dict = tc.dictionary
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			handler := mustNew(&settings)
			client := &Client{Handler: handler, Dict: tc.dictionary}
			if tc.offerCx {
				client.VendorSpecificApplicationID = []*diam.AVP{smVendorApp(16777216, 10415)}
			}
			request, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := buildSuccessCEA(handler, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			for _, message := range []*diam.Message{request, answer} {
				name := "CER"
				if message == answer {
					name = "CEA"
				}
				t.Run(name, func(t *testing.T) {
					got := readSMCapabilities(t, message, tc.dictionary)
					checkSMVendors(t, got.supported, tc.want)
					wantCxGroups := 0
					if tc.offerCx {
						wantCxGroups = 1
					}
					if n := countSMGroup(got.groups, 16777216, 10415, avp.AuthApplicationID); n != wantCxGroups {
						t.Errorf("3GPP Cx groups = %d, want %d", n, wantCxGroups)
					}
					if n := countSMGroup(got.groups, 16777216, 13019, avp.AuthApplicationID); n != 0 {
						t.Errorf("ETSI Cx groups = %d, want 0", n)
					}
				})
			}
		})
	}
}

func TestClientCERAdvertisedVendorsFollowOffers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dictionary *dict.Parser
		offer      *diam.AVP
		want       []uint32
	}{
		{"no-offer", dict.Default, nil, []uint32{5535, 10415, 13019, 45687}},
		{"Default-S6a-only", dict.Default, smVendorApp(16777251, 10415), []uint32{10415}},
		{"Default-Cx-only", dict.Default, smVendorApp(16777216, 10415), []uint32{10415, 13019}},
		{"S6a-bundle", dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.S6c, dict.S6a), smVendorApp(16777251, 10415), []uint32{10415}},
		{"Cx-bundle", dict.New(dict.Base, dict.NASREQ, dict.Cx), smVendorApp(16777216, 10415), []uint32{10415, 13019}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := *serverSettings
			settings.Dict = tc.dictionary
			client := &Client{Handler: mustNew(&settings), Dict: tc.dictionary}
			if tc.offer != nil {
				client.VendorSpecificApplicationID = []*diam.AVP{tc.offer}
			}
			request, err := client.makeCER([]datatype.Address{localhostAddress})
			if err != nil {
				t.Fatal(err)
			}
			got := readSMCapabilities(t, request, tc.dictionary)
			checkSMVendors(t, got.supported, tc.want)
		})
	}
}

func TestS6aBundledCapabilities(t *testing.T) {
	dictionary := dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf, dict.S6c, dict.S6a)
	settings := *serverSettings
	settings.Dict = dictionary
	settings.HostIPAddresses = []datatype.Address{localhostAddress}
	handler := mustNew(&settings)
	client := &Client{Handler: handler, Dict: dictionary,
		VendorSpecificApplicationID: []*diam.AVP{smVendorApp(16777251, 10415)}}
	request, err := client.makeCER(settings.HostIPAddresses)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := buildSuccessCEA(handler, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []*diam.Message{request, answer} {
		got := readSMCapabilities(t, message, dictionary)
		wantVendors := []uint32{10415}
		if message == answer {
			wantVendors = []uint32{5535, 10415, 13019, 45687}
		}
		checkSMVendors(t, got.supported, wantVendors)
		if n := countSMGroup(got.groups, 16777251, 10415, avp.AuthApplicationID); n != 1 {
			t.Errorf("3GPP S6a groups = %d, want 1", n)
		}
	}
}

func TestSMConfiguredSupportedVendors(t *testing.T) {
	dictionary := dict.New(dict.Base, dict.NASREQ, dict.Cx)
	for _, tc := range []struct {
		name           string
		manufacturer   uint32
		settingsVendor []*diam.AVP
		clientVendor   []*diam.AVP
		wantCEA        []uint32
		wantCER        []uint32
	}{
		{"auto-42", 42, nil, nil, []uint32{10415, 13019}, []uint32{10415, 13019}},
		{"auto-own-3gpp", 10415, nil, nil, []uint32{10415, 13019}, []uint32{10415, 13019}},
		{"auto-own-etsi", 13019, nil, nil, []uint32{10415}, []uint32{10415}},
		{"settings-duplicates", 42, []*diam.AVP{smSupportedVendor(13019), smSupportedVendor(42), smSupportedVendor(10415), smSupportedVendor(777), smSupportedVendor(777)}, nil, []uint32{13019, 42, 10415, 777, 777}, []uint32{13019, 42, 10415, 777, 777}},
		{"settings-empty", 42, []*diam.AVP{}, nil, nil, nil},
		{"client-override", 42, []*diam.AVP{smSupportedVendor(777)}, []*diam.AVP{smSupportedVendor(888)}, []uint32{777}, []uint32{888}},
		{"client-empty", 42, []*diam.AVP{smSupportedVendor(777)}, []*diam.AVP{}, []uint32{777}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := *serverSettings
			settings.Dict = dictionary
			settings.VendorID = datatype.Unsigned32(tc.manufacturer)
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			settings.SupportedVendorID = tc.settingsVendor
			handler := mustNew(&settings)
			client := &Client{Handler: handler, Dict: dictionary, SupportedVendorID: tc.clientVendor,
				VendorSpecificApplicationID: []*diam.AVP{smVendorApp(16777216, 10415)}}
			request, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := buildSuccessCEA(handler, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			checkSMVendors(t, readSMCapabilities(t, request, dictionary).supported, tc.wantCER)
			checkSMVendors(t, readSMCapabilities(t, answer, dictionary).supported, tc.wantCEA)
		})
	}
}
