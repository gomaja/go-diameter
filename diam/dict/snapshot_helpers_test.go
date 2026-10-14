package dict

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// dumpSnapshot renders every index of s, one sorted line per entry, so two
// Snapshots can be compared by content.
func dumpSnapshot(s *Snapshot) []string {
	vendor := func(v uint32) string {
		return strconv.FormatUint(uint64(v), 10)
	}
	rules := func(rs []*Rule) string {
		var b []string
		for _, r := range rs {
			b = append(b, fmt.Sprintf("%s/%t/%d/%d/%t/%t", r.AVP, r.Required, r.Min, r.Max, r.MaxSet, r.Fixed))
		}
		return strings.Join(b, ",")
	}
	sig := func(a *AVP) string {
		var enum []string
		for _, e := range a.Data.Enum {
			enum = append(enum, fmt.Sprintf("%d=%s", e.Code, e.Name))
		}
		return fmt.Sprintf("%s|%d|%d|%s(%d)|%s|%s|%s|%s|[%s]|[%s]", a.Name, a.Code, a.VendorID, a.Data.TypeName,
			a.Data.Type, a.Must, a.May, a.MustNot, a.MayEncrypt, strings.Join(enum, ","), rules(a.Data.Rule))
	}
	var lines []string
	for i, app := range s.Apps() {
		lines = append(lines, fmt.Sprintf("APPS %02d %d %s %s", i, app.ID, app.Type, app.Name))
	}
	for k, app := range s.appcode {
		lines = append(lines, fmt.Sprintf("APPCODE %d -> %d %s %s", k, app.ID, app.Type, app.Name))
	}
	for k, app := range s.apptype {
		lines = append(lines, fmt.Sprintf("APPTYPE %d %s -> %d %s %s", k.appID, k.typ, app.ID, app.Type, app.Name))
	}
	for k, c := range s.command {
		lines = append(lines, fmt.Sprintf("CMD %d %d -> %s %s req[%s] ans[%s]", k.appID, k.code, c.Name, c.Short,
			rules(c.Request.Rule), rules(c.Answer.Rule)))
	}
	for k, a := range s.avpcode {
		lines = append(lines, fmt.Sprintf("CODE %d %d %s -> %s", k.appID, k.code, vendor(k.vendorID), sig(a)))
	}
	for k, a := range s.avpname {
		lines = append(lines, fmt.Sprintf("NAME %d %s -> %s", k.appID, k.name, sig(a)))
	}
	sort.Strings(lines)
	return lines
}

func diffDumps(t *testing.T, label string, have, want []string) {
	t.Helper()
	if slices.Equal(have, want) {
		return
	}
	haveSet := make(map[string]bool, len(have))
	for _, l := range have {
		haveSet[l] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, l := range want {
		wantSet[l] = true
	}
	n := 0
	for _, l := range want {
		if !haveSet[l] && n < 20 {
			t.Errorf("%s: missing %s", label, l)
			n++
		}
	}
	for _, l := range have {
		if !wantSet[l] && n < 40 {
			t.Errorf("%s: unexpected %s", label, l)
			n++
		}
	}
	t.Fatalf("%s: %d entries, want %d", label, len(have), len(want))
}
