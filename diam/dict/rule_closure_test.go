package dict

import (
	"fmt"
	"sort"
	"testing"
)

// These references already occur in the older dictionaries. Their definitions
// need separate source and compatibility review before they can be added to the
// shared application scopes. Keep each name explicit so new omissions fail.
// The first list comes from the existing 3GPP charging grouped AVPs and is
// inherited by Gx, S6a, S6c, and SGd.
var legacy3GPPGroupGaps = []string{
	"Application-Port-Identifier", "Change-condition", "Conditional-APN-Aggregate-Max-Bitrate",
	"DCD-Information", "Flow-Number", "IM-Information", "ISUP-Cause-Diagnostic",
	"ISUP-Release-Cause", "Logical-Access-Id", "Media-Component-Number",
	"Physical-Access-Id", "Presence-Reporting-Area-Elements-List",
	"Service-Generic-Information", "Status- AS-Code", "TGPP2-BSID", "TGPP2-MEID",
}

var legacy3GPPServingGaps = []string{"MSC-Number", "SGSN-Name", "SGSN-Realm"}

var knownRuleExceptions = map[uint32][]string{
	1: {"Connection-Info", "NAS-IP-Address", "NAS-IPv6-Address",
		"NAS-Identifier", "Origin-AAA-Protocol", "QoS-Filter-Rule", "State"},
	4: append(append([]string{}, legacy3GPPGroupGaps...), legacy3GPPServingGaps...),
	16777236: {"3GPP-MS-TimeZone", "3GPP-SGSN-MCC-MNC", "3GPP-User-Location-Info",
		"Max-PLR-DL", "Max-PLR-UL", "Netloc-Access-Support", "RS-Bandwidth ",
		"SIP-Forking-Indication ", "Session-Id ", "Sponsored-Connectivity-Data ",
		"Tariff-Change-Usage"},
	16777238: append(append([]string{}, legacy3GPPGroupGaps...), legacy3GPPServingGaps...),
	16777251: append(append(append([]string{}, legacy3GPPGroupGaps...), legacy3GPPServingGaps...),
		"Alert-Reason", "EPS-Location-Information", "EPS-User-State", "Emergency-Services",
		"IDA-Flags", "IMS-Voice-Over-PS-Sessions", "Last-UE-Activity-time", "Local-Time-Zone",
		"Maximum-UE-Availability-Type", "Monitoring-Event-Config-Status",
		"Monitoring-Event-Report", "Reset-ID", "Supported-Services"),
	16777265: {"3GPP-Charging-Characteristics", "Feature-List", "Feature-List-ID", "IMEI",
		"MIP-Home-Agent-Address", "MIP-Home-Agent-Host", "MIP6-Home-Link-Prefix",
		"Software-Version", "TGPP2-MEID"},
	16777302: {"Policy-Counter-Identifier", "Service-Information", "Subscription-Id"},
	16777312: legacy3GPPGroupGaps,
	16777313: legacy3GPPGroupGaps,
}

// TestDefaultRuleClosure keeps command and grouped AVP grammars usable through
// each application's actual lookup scope, including inherited AVPs.
func TestDefaultRuleClosure(t *testing.T) {
	for _, app := range Default.Apps() {
		app := app
		t.Run(fmt.Sprintf("%d/%s", app.ID, app.Name), func(t *testing.T) {
			visited := make(map[string]bool)
			missing := make(map[string]string)
			var check func(string, []*Rule)
			check = func(owner string, rules []*Rule) {
				for _, rule := range rules {
					if rule.AVP == "AVP" { // Diameter's arbitrary AVP wildcard.
						continue
					}
					avp, err := Default.FindAVP(app.ID, rule.AVP)
					if err != nil || avp == nil {
						if _, seen := missing[rule.AVP]; !seen {
							missing[rule.AVP] = owner
						}
						continue
					}
					if avp.Data.TypeName == "Grouped" && !visited[avp.Name] {
						visited[avp.Name] = true
						check(owner+"/"+avp.Name, avp.Data.Rule)
					}
				}
			}
			for _, cmd := range app.Command {
				check(cmd.Name+" request", cmd.Request.Rule)
				check(cmd.Name+" answer", cmd.Answer.Rule)
			}
			// Include inherited groups even when no command in this app names them.
			for idx, avp := range Default.avpname {
				if idx.appID != app.ID || idx.vendorID != UndefinedVendorID {
					continue
				}
				if avp.Data.TypeName == "Grouped" && !visited[avp.Name] {
					visited[avp.Name] = true
					check(avp.Name, avp.Data.Rule)
				}
			}
			var names []string
			for name := range missing {
				names = append(names, name)
			}
			sort.Strings(names)
			expected := make(map[string]bool)
			for _, name := range knownRuleExceptions[app.ID] {
				expected[name] = true
				if _, ok := missing[name]; !ok {
					t.Errorf("stale exception for resolved AVP %q", name)
				}
			}
			for _, name := range names {
				if !expected[name] {
					t.Errorf("unresolved AVP %q (via %s)", name, missing[name])
				}
			}
		})
	}
}
