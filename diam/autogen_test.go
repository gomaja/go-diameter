package diam

import (
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAutogenExportsIdentifiers(t *testing.T) {
	requireAutogenTools(t)
	dir := t.TempDir()
	for _, name := range []string{"dict/fixtures", "avp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("autogen.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autogen.sh"), script, 0600); err != nil {
		t.Fatal(err)
	}
	const fixture = `<diameter>
<application id="123" type="auth" name="lowercase app">
<command code="456" short="lc" name="lowercase-command">
<request/>
<answer/>
</command>
<avp name="eDRX-Related-RAT" code="1705"><data type="Grouped"/></avp>
<avp name="eDRX-Cycle-Length" code="1691"><data type="Unsigned32"/></avp>
<avp name="9-Test" code="999"><data type="Unsigned32"/></avp>
</application>
</diameter>`
	writeAutogenManifest(t, dir, []string{"dict/fixtures/fixture.xml"})
	if err := os.WriteFile(filepath.Join(dir, "dict/fixtures/fixture.xml"), []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "autogen.sh")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autogen: %v\n%s", err, out)
	}
	expected := map[string][]string{
		"commands.go":     {"Lowercasecommand", "LcR", "LcA"},
		"applications.go": {"LOWERCASE_APP_APP_ID"},
		"avp/codes.go":    {"EDRXRelatedRAT", "EDRXCycleLength", "X9Test"},
	}
	for name, want := range expected {
		seen := make(map[string]bool)
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				for _, id := range spec.(*ast.ValueSpec).Names {
					seen[id.Name] = true
					if !id.IsExported() {
						t.Errorf("%s: generated identifier %s is not exported", name, id.Name)
					}
				}
			}
		}
		for _, id := range want {
			if !seen[id] {
				t.Errorf("%s: missing generated identifier %s", name, id)
			}
		}
	}
}

// requireAutogenTools skips the test where autogen.sh cannot run: it needs a
// POSIX shell, awk, sort, the go command, and GNU sed for the \u replacement,
// which it takes from gsed on macOS.
func requireAutogenTools(t *testing.T) {
	t.Helper()
	sed := "sed"
	if runtime.GOOS == "darwin" {
		sed = "gsed"
	}
	for _, tool := range []string{"sh", "awk", "sort", "go", sed} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("autogen.sh needs %s: %v", tool, err)
		}
	}
}

// TestGeneratedFilesAreCurrent runs autogen.sh on the bundled dictionaries
// and requires the committed constants to match, so a dictionary change
// cannot land without the constants it generates.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	requireAutogenTools(t)
	dir := t.TempDir()
	for _, name := range []string{"dict/fixtures", "avp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(src, dst string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("autogen.sh", filepath.Join(dir, "autogen.sh"))
	paths := autogenSourcePaths(t)
	writeAutogenManifest(t, dir, paths)
	for _, src := range paths {
		copyFile(src, filepath.Join(dir, src))
	}
	cmd := exec.Command("sh", "autogen.sh")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autogen: %v\n%s", err, out)
	}
	for _, name := range []string{"commands.go", "applications.go", filepath.Join("avp", "codes.go")} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout may convert the committed files to CRLF.
		if g, w := lf(got), lf(want); g != w {
			gl, wl := strings.Split(g, "\n"), strings.Split(w, "\n")
			i := 0
			for i < len(gl) && i < len(wl) && gl[i] == wl[i] {
				i++
			}
			var gotLine, wantLine string
			if i < len(gl) {
				gotLine = gl[i]
			}
			if i < len(wl) {
				wantLine = wl[i]
			}
			t.Errorf("%s is out of date at line %d: have %q, generated %q; run sh autogen.sh in diam/", name, i+1, gotLine, wantLine)
		}
	}
}

func lf(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }

// Each declaration gets a unique name so a duplicate in another dictionary
// cannot mask a missed tag. All attribute orders and multiline tags are covered.
func TestAutogenEveryBundledCommand(t *testing.T) {
	requireAutogenTools(t)
	dir := t.TempDir()
	for _, name := range []string{"dict/fixtures", "avp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("autogen.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autogen.sh"), script, 0600); err != nil {
		t.Fatal(err)
	}
	paths := autogenSourcePaths(t)
	var body strings.Builder
	body.WriteString(`<diameter><application name="Command test" inherits="0" id="42">` + "\n")
	want := map[string]string{}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	count := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), raw, 0600); err != nil {
			t.Fatal(err)
		}
		var f struct {
			Apps []struct {
				Commands []struct {
					Code  uint32 `xml:"code,attr"`
					Name  string `xml:"name,attr"`
					Short string `xml:"short,attr"`
				} `xml:"command"`
			} `xml:"application"`
		}
		if err := xml.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		for _, app := range f.Apps {
			for _, c := range app.Commands {
				exported := func(name string) string {
					name = strings.ReplaceAll(name, "-", "")
					return strings.ToUpper(name[:1]) + name[1:]
				}
				if c.Name == "" || c.Short == "" {
					t.Fatalf("command %d in %s lacks name/short", c.Code, path)
				}
				want[exported(c.Name)] = strconv.FormatUint(uint64(c.Code), 10)
				want[exported(c.Short)+"R"] = strconv.Quote(strings.ReplaceAll(c.Short, "-", "") + "R")
				want[exported(c.Short)+"A"] = strconv.Quote(strings.ReplaceAll(c.Short, "-", "") + "A")
				count++
				for permutation, order := range orders {
					name := fmt.Sprintf("Declaration%dOrder%d", count, permutation)
					short := fmt.Sprintf("D%dO%d", count, permutation)
					attrs := []string{fmt.Sprintf(`code="%d"`, c.Code), `name="` + name + `"`, `short="` + short + `"`}
					separator := " "
					if permutation%2 == 1 {
						separator = "\n "
					}
					fmt.Fprintf(&body, "<command %s%s%s%s%s><request/><answer/></command>\n", attrs[order[0]], separator, attrs[order[1]], separator, attrs[order[2]])
					want[name] = strconv.FormatUint(uint64(c.Code), 10)
					want[short+"R"] = strconv.Quote(short + "R")
					want[short+"A"] = strconv.Quote(short + "A")
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("no bundled commands")
	}
	body.WriteString("</application></diameter>")
	writeAutogenManifest(t, dir, append(paths, "dict/fixtures/commands.xml"))
	if err := os.WriteFile(filepath.Join(dir, "dict/fixtures/commands.xml"), []byte(body.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "autogen.sh")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autogen: %v\n%s", err, output)
	}
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "commands.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, decl := range f.Decls {
		if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.CONST {
			for _, spec := range g.Specs {
				v := spec.(*ast.ValueSpec)
				if len(v.Values) == 1 {
					if value, ok := v.Values[0].(*ast.BasicLit); ok {
						got[v.Names[0].Name] = value.Value
					}
				}
			}
		}
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %q, want %s", name, got[name], value)
		}
	}
	t.Logf("checked %d bundled command declarations in all six attribute orders", count)
}

func autogenSourcePaths(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("dict/sources.txt")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			paths = append(paths, filepath.Join("dict", line))
		}
	}
	if len(paths) != 14 {
		t.Fatalf("source manifest has %d sources, want 14", len(paths))
	}
	return paths
}
func writeAutogenManifest(t *testing.T, dir string, paths []string) {
	t.Helper()
	manifest := make([]string, len(paths))
	for i, p := range paths {
		manifest[i] = strings.TrimPrefix(filepath.ToSlash(p), "dict/")
	}
	if err := os.WriteFile(filepath.Join(dir, "dict/sources.txt"), []byte(strings.Join(manifest, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
