package dict

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Transcribed from 3GPP TS 29.272 V19.6.0 §§7.2.3–7.2.20.
// The spec prints "IDR- Flags" in §7.2.9; the registered AVP spelling is IDR-Flags.
// A bare angle bracket is fixed only for the initial Session-Id here.
var s6aS13CommandABNF = []struct {
	section   string
	code, app uint32
	request   bool
	grammar   string
}{
	{"7.2.3", 316, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Destination-Host ]
{ Destination-Realm }
{ User-Name }
[ OC-Supported-Features ]
*[ Supported-Features ]
[ Terminal-Information ]
{ RAT-Type }
{ ULR-Flags }
[ UE-SRVCC-Capability ]
{ Visited-PLMN-Id }
[ SGSN-Number ]
[ Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions ]
[ GMLC-Address ]
*[ Active-APN ]
[ Equivalent-PLMN-List ]
[ MME-Number-for-MT-SMS ]
[ SMS-Register-Request ]
[ SGs-MME-Identity ]
[ Coupled-Node-Diameter-ID ]
[ Adjacent-PLMNs ]
[ Supported-Services ]
[ SF-ULR-Timestamp ]
[ SF-Provisional-Indication ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.4", 316, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
[ Result-Code ]
[ Experimental-Result ]
[ Error-Diagnostic ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ OC-Supported-Features ]
[ OC-OLR ]
*[ Load ]
*[ Supported-Features ]
[ ULA-Flags ]
[ Subscription-Data ]
*[ Reset-ID ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.5", 318, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Destination-Host ]
{ Destination-Realm }
{ User-Name }
[ OC-Supported-Features ]
*[Supported-Features]
[ Requested-EUTRAN-Authentication-Info ]
[ Requested-UTRAN-GERAN-Authentication-Info ]
{ Visited-PLMN-Id }
[ AIR-Flags ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.6", 318, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
[ Result-Code ]
[ Experimental-Result ]
[ Error-Diagnostic ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ OC-Supported-Features ]
[ OC-OLR ]
*[ Load ]
*[Supported-Features]
[ Authentication-Info ]
[ UE-Usage-Type ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.7", 317, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
{ Destination-Host }
{ Destination-Realm }
{ User-Name }
*[Supported-Features ]
{ Cancellation-Type }
[ CLR-Flags ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.8", 317, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
*[ Supported-Features ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.9", 319, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
{ Destination-Host }
{ Destination-Realm }
{ User-Name }
*[ Supported-Features ]
{ Subscription-Data }
[ IDR-Flags ]
*[ Reset-ID ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.10", 319, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
*[ Supported-Features ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ IMS-Voice-Over-PS-Sessions-Supported ]
[ Last-UE-Activity-Time ]
[ RAT-Type ]
[ IDA-Flags ]
[ EPS-User-State ]
[ EPS-Location-Information ]
[Local-Time-Zone ]
[ Supported-Services ]
*[ Monitoring-Event-Report ]
*[ Monitoring-Event-Config-Status ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.11", 320, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
{ Destination-Host }
{ Destination-Realm }
{ User-Name }
*[ Supported-Features ]
{ DSR-Flags }
[ SCEF-ID ]
*[ Context-Identifier ]
[ Trace-Reference ]
*[ TS-Code ]
*[ SS-Code ]
[ eDRX-Related-RAT ]
*[ External-Identifier ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.12", 320, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
*[ Supported-Features ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ DSA-Flags ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.13", 321, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Destination-Host ]
{ Destination-Realm }
{ User-Name }
[ OC-Supported-Features ]
[ PUR-Flags ]
*[ Supported-Features ]
[ EPS-Location-Information ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.14", 321, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
*[ Supported-Features ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ OC-Supported-Features ]
[ OC-OLR ]
*[ Load ]
[ PUA-Flags ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.15", 322, 16777251, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
{ Destination-Host }
{ Destination-Realm }
*[ Supported-Features ]
*[ User-Id ]
*[ Reset-ID ]
[ Subscription-Data ]
[ Subscription-Data-Deletion ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.16", 322, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
*[ Supported-Features ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.17", 323, 16777251, true, `
< Session-Id >
[ Vendor-Specific-Application-Id ]
[ DRMP ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Destination-Host ]
{ Destination-Realm }
{ User-Name }
[ OC-Supported-Features ]
*[ Supported-Features ]
[ Terminal-Information ]
[ MIP6-Agent-Info ]
[ Visited-Network-Identifier ]
[ Context-Identifier ]
[Service-Selection]
[ Alert-Reason ]
[ UE-SRVCC-Capability ]
[ NOR-Flags ]
[ Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions ]
[ Maximum-UE-Availability-Time ]
*[ Monitoring-Event-Config-Status ]
[ Emergency-Services ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.18", 323, 16777251, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ OC-Supported-Features ]
[ OC-OLR ]
*[ Load ]
*[ Supported-Features ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.19", 324, 16777252, true, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Destination-Host ]
{ Destination-Realm }
{ Terminal-Information }
[ User-Name ]
*[ AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
	{"7.2.20", 324, 16777252, false, `
< Session-Id >
[ DRMP ]
[ Vendor-Specific-Application-Id ]
[ Result-Code ]
[ Experimental-Result ]
{ Auth-Session-State }
{ Origin-Host }
{ Origin-Realm }
[ Equipment-Status ]
*[ AVP ]
[ Failed-AVP ]
*[ Proxy-Info ]
*[ Route-Record ]
`},
}

var commandABNFToken = regexp.MustCompile(`^(\*)?([<\[{])\s*([^>}\]]+?)\s*[>}\]]$`)

func transcribeCommandRules(t *testing.T, grammar string) []*Rule {
	t.Helper()
	var rules []*Rule
	for _, line := range strings.Split(strings.TrimSpace(grammar), "\n") {
		line = strings.TrimSpace(line)
		match := commandABNFToken.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("unrecognized ABNF rule %q", line)
		}
		name := strings.TrimSpace(match[3])
		rule := &Rule{AVP: name, Required: match[2] == "<" || match[2] == "{", Fixed: match[2] == "<"}
		if match[1] == "" {
			rule.Max = 1
			rule.MaxSet = true
		}
		rules = append(rules, rule)
	}
	return rules
}

func TestS6aS13CommandABNFSpec(t *testing.T) {
	for _, tc := range s6aS13CommandABNF {
		t.Run(tc.section, func(t *testing.T) {
			command, err := Default.FindCommand(tc.app, tc.code)
			if err != nil {
				t.Fatal(err)
			}
			var actual CommandRule
			if tc.request {
				actual = command.Request
			} else {
				actual = command.Answer
			}
			if actual.Proxiable == nil || !*actual.Proxiable {
				t.Errorf("PXY bit: got %v, want required", actual.Proxiable)
			}
			expected := transcribeCommandRules(t, tc.grammar)
			if len(actual.Rule) != len(expected) {
				t.Errorf("rule count: got %d, want %d", len(actual.Rule), len(expected))
			}
			for i := 0; i < len(actual.Rule) && i < len(expected); i++ {
				got, want := actual.Rule[i], expected[i]
				if !reflect.DeepEqual(got, want) {
					t.Errorf("rule %d: got %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// Compile-time references also ensure the fixtures cover nine request/answer pairs.
func TestS6aS13CommandABNFPairCoverage(t *testing.T) {
	if len(s6aS13CommandABNF) != 18 {
		t.Fatalf("got %d command formats, want 18", len(s6aS13CommandABNF))
	}
	counts := map[string]int{}
	for _, tc := range s6aS13CommandABNF {
		counts[fmt.Sprint(tc.app, "/", tc.code)]++
	}
	for key, count := range counts {
		if count != 2 {
			t.Errorf("%s: got %d formats, want request and answer", key, count)
		}
	}
}
