package dict_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/dict/all"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/dict/cx"
	"github.com/gomaja/go-diameter/diam/dict/gx"
	"github.com/gomaja/go-diameter/diam/dict/nasreq"
	"github.com/gomaja/go-diameter/diam/dict/rorf"
	"github.com/gomaja/go-diameter/diam/dict/rx"
	"github.com/gomaja/go-diameter/diam/dict/s13"
	"github.com/gomaja/go-diameter/diam/dict/s6a"
	"github.com/gomaja/go-diameter/diam/dict/s6c"
	"github.com/gomaja/go-diameter/diam/dict/sgd"
	"github.com/gomaja/go-diameter/diam/dict/sh"
	"github.com/gomaja/go-diameter/diam/dict/swx"
	"github.com/gomaja/go-diameter/diam/dict/sy"
)

func newAllTestParser(t testing.TB) *dict.Parser {
	t.Helper()
	return newTestParser(t, all.Dictionary())
}

func newTestParser(t testing.TB, dictionaries ...dict.Dictionary) *dict.Parser {
	t.Helper()
	p, err := dict.New(dictionaries...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// These source closures are independent expectations from the accepted
// application dependency design, not values obtained from descriptors.
func applicationSelections() []struct {
	name       string
	dictionary dict.Dictionary
	sources    []string
} {
	charging := []string{"base.xml", "credit_control.xml", "network_access_server.xml", "tgpp_ro_rf.xml"}
	with := func(names ...string) []string {
		result := append(slices.Clone(charging), names...)
		sort.Strings(result)
		return result
	}
	return []struct {
		name       string
		dictionary dict.Dictionary
		sources    []string
	}{
		{"base.xml", dict.Base(), []string{"base.xml"}},
		{"credit_control.xml", creditcontrol.Dictionary(), slices.Clone(charging)},
		{"diameter_sy.xml", sy.Dictionary(), with("diameter_sy.xml")},
		{"gx_credit_control.xml", gx.Dictionary(), with("gx_credit_control.xml")},
		{"network_access_server.xml", nasreq.Dictionary(), []string{"base.xml", "network_access_server.xml"}},
		{"tgpp_cx.xml", cx.Dictionary(), []string{"base.xml", "network_access_server.xml", "tgpp_cx.xml"}},
		{"tgpp_ro_rf.xml", rorf.Dictionary(), slices.Clone(charging)},
		{"tgpp_rx.xml", rx.Dictionary(), with("tgpp_rx.xml")},
		{"tgpp_s13.xml", s13.Dictionary(), []string{"base.xml", "tgpp_s13.xml"}},
		{"tgpp_s6a.xml", s6a.Dictionary(), with("tgpp_s6a.xml", "tgpp_s6c.xml")},
		{"tgpp_s6c.xml", s6c.Dictionary(), with("tgpp_s6c.xml")},
		{"tgpp_sgd.xml", sgd.Dictionary(), with("tgpp_s6c.xml", "tgpp_sgd.xml")},
		{"tgpp_sh.xml", sh.Dictionary(), []string{"base.xml", "network_access_server.xml", "tgpp_cx.xml", "tgpp_sh.xml"}},
		{"tgpp_swx.xml", swx.Dictionary(), with("tgpp_s6a.xml", "tgpp_s6c.xml", "tgpp_swx.xml")},
	}
}

func manifestSources(t testing.TB) map[string]string {
	t.Helper()
	data, err := os.ReadFile("sources.txt")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for _, source := range strings.Fields(string(data)) {
		name := filepath.Base(source)
		if _, duplicate := result[name]; duplicate {
			t.Fatalf("duplicate manifest source %s", name)
		}
		result[name] = source
	}
	return result
}
func sourceNames(t testing.TB) []string {
	t.Helper()
	var names []string
	for name := range manifestSources(t) {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func sourcePath(t testing.TB, name string) string {
	t.Helper()
	source, found := manifestSources(t)[name]
	if !found {
		t.Fatalf("source %q missing from manifest", name)
	}
	return source
}
func sourceApps(t testing.TB, name string) []*dict.App {
	t.Helper()
	data, err := os.ReadFile(sourcePath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	file, err := dict.ParseXMLForTesting(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return file.App
}
func dumpSnapshot(s *dict.Snapshot) []string { return dict.DumpSnapshotForTesting(s) }
func diffDumps(t *testing.T, label string, have, want []string) {
	t.Helper()
	if slices.Equal(have, want) {
		return
	}
	haveSet, wantSet := make(map[string]bool), make(map[string]bool)
	for _, line := range have {
		haveSet[line] = true
	}
	for _, line := range want {
		wantSet[line] = true
	}
	n := 0
	for _, line := range want {
		if !haveSet[line] && n < 20 {
			t.Errorf("%s: missing %s", label, line)
			n++
		}
	}
	for _, line := range have {
		if !wantSet[line] && n < 40 {
			t.Errorf("%s: unexpected %s", label, line)
			n++
		}
	}
	t.Fatalf("%s: %d entries, want %d", label, len(have), len(want))
}

type vendorLookup interface {
	FindAVP(uint32, uint32, uint32) (*dict.AVP, error)
	FindAVPByName(uint32, string) (*dict.AVP, error)
	Enum(uint32, uint32, uint32, int32) (*dict.Enum, error)
	Rule(uint32, uint32, uint32, string) (*dict.Rule, error)
	App(uint32, ...string) (*dict.App, error)
}
