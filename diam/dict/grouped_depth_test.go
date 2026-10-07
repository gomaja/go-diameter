package dict

import (
	"fmt"
	"strings"
	"testing"
)

// TestDefaultGroupedNestingWithinLimit keeps DefaultMaxGroupedDepth above the
// deepest Grouped nesting that the named rules of the shipped command
// grammars allow, so the decoder's nesting limit does not reject a message
// built from them. A cycle through named Grouped rules fails too. The
// *[ AVP ] wildcard admits arbitrary nesting and is not followed.
func TestDefaultGroupedNestingWithinLimit(t *testing.T) {
	deepest, deepestPath := 0, ""
	for _, app := range Default.Apps() {
		// chain memoizes the deepest Grouped chain below each AVP, itself first.
		chain := make(map[string][]string)
		onPath := make(map[string]bool)
		var measure func(avp *AVP, path []string) []string
		measure = func(avp *AVP, path []string) []string {
			if onPath[avp.Name] {
				t.Errorf("app %d: Grouped rule cycle: %s > %s", app.ID, strings.Join(path, " > "), avp.Name)
				return nil
			}
			if c, ok := chain[avp.Name]; ok {
				return c
			}
			onPath[avp.Name] = true
			var below []string
			for _, rule := range avp.Data.Rule {
				if rule.AVP == "AVP" { // Diameter's arbitrary AVP wildcard.
					continue
				}
				child, err := Default.FindAVPByName(app.ID, rule.AVP)
				if err != nil || child == nil || child.Data.TypeName != "Grouped" {
					continue
				}
				if c := measure(child, append(path, avp.Name)); len(c) > len(below) {
					below = c
				}
			}
			onPath[avp.Name] = false
			c := append([]string{avp.Name}, below...)
			chain[avp.Name] = c
			return c
		}
		for _, cmd := range app.Command {
			for _, rules := range [][]*Rule{cmd.Request.Rule, cmd.Answer.Rule} {
				for _, rule := range rules {
					avp, err := Default.FindAVPByName(app.ID, rule.AVP)
					if err != nil || avp == nil || avp.Data.TypeName != "Grouped" {
						continue
					}
					if c := measure(avp, nil); len(c) > deepest {
						deepest = len(c)
						deepestPath = fmt.Sprintf("app %d %s: %s", app.ID, cmd.Short, strings.Join(c, " > "))
					}
				}
			}
		}
	}
	t.Logf("deepest Grouped nesting: %d levels (%s)", deepest, deepestPath)
	if deepest == 0 {
		t.Fatal("found no Grouped AVPs in the command grammars")
	}
	if deepest*2 > DefaultMaxGroupedDepth {
		t.Fatalf("grammar nests %d levels; DefaultMaxGroupedDepth %d leaves less than 2x headroom",
			deepest, DefaultMaxGroupedDepth)
	}
}
