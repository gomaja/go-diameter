package dict

import (
	"fmt"
	"sort"
	"testing"
)

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
			for _, name := range names {
				t.Errorf("unresolved AVP %q (via %s)", name, missing[name])
			}
		})
	}
}
